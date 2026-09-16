rule TTP_XOR_WriteProcessMemory_d2b8 {
  strings:
    $key_d2b8 = { 85 ca [2] b7 e8 [2] b1 dd [2] 9f dd [2] a0 c1 }

  condition:
    any of them
}