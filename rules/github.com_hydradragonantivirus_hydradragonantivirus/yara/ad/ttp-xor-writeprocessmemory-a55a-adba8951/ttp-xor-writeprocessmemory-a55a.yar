rule TTP_XOR_WriteProcessMemory_a55a {
  strings:
    $key_a55a = { f2 28 [2] c0 0a [2] c6 3f [2] e8 3f [2] d7 23 }

  condition:
    any of them
}