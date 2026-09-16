rule TTP_XOR_WriteProcessMemory_23b8 {
  strings:
    $key_23b8 = { 74 ca [2] 46 e8 [2] 40 dd [2] 6e dd [2] 51 c1 }

  condition:
    any of them
}