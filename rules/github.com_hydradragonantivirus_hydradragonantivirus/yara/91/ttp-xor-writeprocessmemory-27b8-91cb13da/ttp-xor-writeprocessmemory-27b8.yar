rule TTP_XOR_WriteProcessMemory_27b8 {
  strings:
    $key_27b8 = { 70 ca [2] 42 e8 [2] 44 dd [2] 6a dd [2] 55 c1 }

  condition:
    any of them
}