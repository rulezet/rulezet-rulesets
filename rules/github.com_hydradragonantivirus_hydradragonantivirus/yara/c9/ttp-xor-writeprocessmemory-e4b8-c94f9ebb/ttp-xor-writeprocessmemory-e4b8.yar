rule TTP_XOR_WriteProcessMemory_e4b8 {
  strings:
    $key_e4b8 = { b3 ca [2] 81 e8 [2] 87 dd [2] a9 dd [2] 96 c1 }

  condition:
    any of them
}