rule TTP_XOR_WriteProcessMemory_3d21 {
  strings:
    $key_3d21 = { 6a 53 [2] 58 71 [2] 5e 44 [2] 70 44 [2] 4f 58 }

  condition:
    any of them
}