rule TTP_XOR_WriteProcessMemory_60b8 {
  strings:
    $key_60b8 = { 37 ca [2] 05 e8 [2] 03 dd [2] 2d dd [2] 12 c1 }

  condition:
    any of them
}