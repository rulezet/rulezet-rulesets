rule TTP_XOR_WriteProcessMemory_a71a {
  strings:
    $key_a71a = { f0 68 [2] c2 4a [2] c4 7f [2] ea 7f [2] d5 63 }

  condition:
    any of them
}