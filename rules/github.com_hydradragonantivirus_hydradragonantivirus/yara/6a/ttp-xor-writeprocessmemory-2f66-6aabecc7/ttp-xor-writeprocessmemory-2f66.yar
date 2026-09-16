rule TTP_XOR_WriteProcessMemory_2f66 {
  strings:
    $key_2f66 = { 78 14 [2] 4a 36 [2] 4c 03 [2] 62 03 [2] 5d 1f }

  condition:
    any of them
}