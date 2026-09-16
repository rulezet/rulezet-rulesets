rule TTP_XOR_WriteProcessMemory_4833 {
  strings:
    $key_4833 = { 1f 41 [2] 2d 63 [2] 2b 56 [2] 05 56 [2] 3a 4a }

  condition:
    any of them
}