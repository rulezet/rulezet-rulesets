rule TTP_XOR_WriteProcessMemory_3548 {
  strings:
    $key_3548 = { 62 3a [2] 50 18 [2] 56 2d [2] 78 2d [2] 47 31 }

  condition:
    any of them
}