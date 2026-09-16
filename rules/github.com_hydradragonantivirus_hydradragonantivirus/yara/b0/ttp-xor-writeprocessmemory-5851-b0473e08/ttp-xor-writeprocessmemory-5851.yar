rule TTP_XOR_WriteProcessMemory_5851 {
  strings:
    $key_5851 = { 0f 23 [2] 3d 01 [2] 3b 34 [2] 15 34 [2] 2a 28 }

  condition:
    any of them
}