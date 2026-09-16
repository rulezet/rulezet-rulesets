rule TTP_XOR_WriteProcessMemory_d7b8 {
  strings:
    $key_d7b8 = { 80 ca [2] b2 e8 [2] b4 dd [2] 9a dd [2] a5 c1 }

  condition:
    any of them
}