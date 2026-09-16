rule TTP_XOR_WriteProcessMemory_7060 {
  strings:
    $key_7060 = { 27 12 [2] 15 30 [2] 13 05 [2] 3d 05 [2] 02 19 }

  condition:
    any of them
}