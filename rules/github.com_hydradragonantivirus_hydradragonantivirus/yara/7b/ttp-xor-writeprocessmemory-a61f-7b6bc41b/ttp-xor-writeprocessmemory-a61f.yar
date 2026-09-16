rule TTP_XOR_WriteProcessMemory_a61f {
  strings:
    $key_a61f = { f1 6d [2] c3 4f [2] c5 7a [2] eb 7a [2] d4 66 }

  condition:
    any of them
}