rule TTP_XOR_WriteProcessMemory_2f71 {
  strings:
    $key_2f71 = { 78 03 [2] 4a 21 [2] 4c 14 [2] 62 14 [2] 5d 08 }

  condition:
    any of them
}