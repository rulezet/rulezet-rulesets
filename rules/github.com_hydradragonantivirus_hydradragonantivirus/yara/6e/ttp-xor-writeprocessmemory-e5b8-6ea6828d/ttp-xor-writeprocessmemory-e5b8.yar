rule TTP_XOR_WriteProcessMemory_e5b8 {
  strings:
    $key_e5b8 = { b2 ca [2] 80 e8 [2] 86 dd [2] a8 dd [2] 97 c1 }

  condition:
    any of them
}