rule TTP_XOR_WriteProcessMemory_a5f8 {
  strings:
    $key_a5f8 = { f2 8a [2] c0 a8 [2] c6 9d [2] e8 9d [2] d7 81 }

  condition:
    any of them
}