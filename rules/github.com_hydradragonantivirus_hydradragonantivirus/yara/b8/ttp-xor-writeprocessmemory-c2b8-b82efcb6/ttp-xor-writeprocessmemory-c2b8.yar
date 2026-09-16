rule TTP_XOR_WriteProcessMemory_c2b8 {
  strings:
    $key_c2b8 = { 95 ca [2] a7 e8 [2] a1 dd [2] 8f dd [2] b0 c1 }

  condition:
    any of them
}