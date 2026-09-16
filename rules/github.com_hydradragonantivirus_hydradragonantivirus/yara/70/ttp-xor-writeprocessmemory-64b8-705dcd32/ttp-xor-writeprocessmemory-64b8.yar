rule TTP_XOR_WriteProcessMemory_64b8 {
  strings:
    $key_64b8 = { 33 ca [2] 01 e8 [2] 07 dd [2] 29 dd [2] 16 c1 }

  condition:
    any of them
}