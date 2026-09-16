rule TTP_XOR_WriteProcessMemory_75b8 {
  strings:
    $key_75b8 = { 22 ca [2] 10 e8 [2] 16 dd [2] 38 dd [2] 07 c1 }

  condition:
    any of them
}