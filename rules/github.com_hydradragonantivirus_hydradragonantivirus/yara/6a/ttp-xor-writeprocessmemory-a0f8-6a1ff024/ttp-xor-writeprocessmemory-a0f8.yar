rule TTP_XOR_WriteProcessMemory_a0f8 {
  strings:
    $key_a0f8 = { f7 8a [2] c5 a8 [2] c3 9d [2] ed 9d [2] d2 81 }

  condition:
    any of them
}