rule TTP_XOR_WriteProcessMemory_a61a {
  strings:
    $key_a61a = { f1 68 [2] c3 4a [2] c5 7f [2] eb 7f [2] d4 63 }

  condition:
    any of them
}