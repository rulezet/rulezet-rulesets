rule TTP_XOR_WriteProcessMemory_a72a {
  strings:
    $key_a72a = { f0 58 [2] c2 7a [2] c4 4f [2] ea 4f [2] d5 53 }

  condition:
    any of them
}