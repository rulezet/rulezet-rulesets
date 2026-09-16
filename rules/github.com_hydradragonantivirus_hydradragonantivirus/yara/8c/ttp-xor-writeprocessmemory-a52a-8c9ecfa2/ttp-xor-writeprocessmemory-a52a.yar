rule TTP_XOR_WriteProcessMemory_a52a {
  strings:
    $key_a52a = { f2 58 [2] c0 7a [2] c6 4f [2] e8 4f [2] d7 53 }

  condition:
    any of them
}