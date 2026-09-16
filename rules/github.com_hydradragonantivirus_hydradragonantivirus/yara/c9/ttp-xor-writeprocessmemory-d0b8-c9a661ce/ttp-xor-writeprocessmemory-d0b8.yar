rule TTP_XOR_WriteProcessMemory_d0b8 {
  strings:
    $key_d0b8 = { 87 ca [2] b5 e8 [2] b3 dd [2] 9d dd [2] a2 c1 }

  condition:
    any of them
}