rule TTP_XOR_WriteProcessMemory_c5b8 {
  strings:
    $key_c5b8 = { 92 ca [2] a0 e8 [2] a6 dd [2] 88 dd [2] b7 c1 }

  condition:
    any of them
}