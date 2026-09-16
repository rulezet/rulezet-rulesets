rule TTP_XOR_WriteProcessMemory_45b8 {
  strings:
    $key_45b8 = { 12 ca [2] 20 e8 [2] 26 dd [2] 08 dd [2] 37 c1 }

  condition:
    any of them
}