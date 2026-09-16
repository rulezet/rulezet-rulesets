rule TTP_XOR_WriteProcessMemory_46b8 {
  strings:
    $key_46b8 = { 11 ca [2] 23 e8 [2] 25 dd [2] 0b dd [2] 34 c1 }

  condition:
    any of them
}