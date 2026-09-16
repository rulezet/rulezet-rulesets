rule TTP_XOR_WriteProcessMemory_6a21 {
  strings:
    $key_6a21 = { 3d 53 [2] 0f 71 [2] 09 44 [2] 27 44 [2] 18 58 }

  condition:
    any of them
}