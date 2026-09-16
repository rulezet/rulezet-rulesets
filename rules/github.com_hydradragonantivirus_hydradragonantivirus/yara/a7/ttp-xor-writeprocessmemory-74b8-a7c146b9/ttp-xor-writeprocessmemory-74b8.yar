rule TTP_XOR_WriteProcessMemory_74b8 {
  strings:
    $key_74b8 = { 23 ca [2] 11 e8 [2] 17 dd [2] 39 dd [2] 06 c1 }

  condition:
    any of them
}