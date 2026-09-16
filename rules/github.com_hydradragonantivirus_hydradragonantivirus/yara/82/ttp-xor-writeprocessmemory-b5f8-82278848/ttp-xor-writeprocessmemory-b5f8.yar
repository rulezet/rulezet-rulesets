rule TTP_XOR_WriteProcessMemory_b5f8 {
  strings:
    $key_b5f8 = { e2 8a [2] d0 a8 [2] d6 9d [2] f8 9d [2] c7 81 }

  condition:
    any of them
}