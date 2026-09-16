rule TTP_XOR_WriteProcessMemory_b548 {
  strings:
    $key_b548 = { e2 3a [2] d0 18 [2] d6 2d [2] f8 2d [2] c7 31 }

  condition:
    any of them
}