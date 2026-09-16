rule TTP_XOR_WriteProcessMemory_6a71 {
  strings:
    $key_6a71 = { 3d 03 [2] 0f 21 [2] 09 14 [2] 27 14 [2] 18 08 }

  condition:
    any of them
}