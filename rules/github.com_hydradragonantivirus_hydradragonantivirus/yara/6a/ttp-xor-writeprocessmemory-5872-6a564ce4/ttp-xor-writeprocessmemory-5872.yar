rule TTP_XOR_WriteProcessMemory_5872 {
  strings:
    $key_5872 = { 0f 00 [2] 3d 22 [2] 3b 17 [2] 15 17 [2] 2a 0b }

  condition:
    any of them
}