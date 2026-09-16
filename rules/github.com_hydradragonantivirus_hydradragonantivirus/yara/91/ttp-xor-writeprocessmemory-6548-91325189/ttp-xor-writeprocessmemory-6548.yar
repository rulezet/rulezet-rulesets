rule TTP_XOR_WriteProcessMemory_6548 {
  strings:
    $key_6548 = { 32 3a [2] 00 18 [2] 06 2d [2] 28 2d [2] 17 31 }

  condition:
    any of them
}