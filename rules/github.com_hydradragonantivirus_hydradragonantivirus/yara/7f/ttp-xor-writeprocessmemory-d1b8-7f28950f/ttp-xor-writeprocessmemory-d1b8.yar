rule TTP_XOR_WriteProcessMemory_d1b8 {
  strings:
    $key_d1b8 = { 86 ca [2] b4 e8 [2] b2 dd [2] 9c dd [2] a3 c1 }

  condition:
    any of them
}