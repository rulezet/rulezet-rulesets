rule TTP_XOR_WriteProcessMemory_86b8 {
  strings:
    $key_86b8 = { d1 ca [2] e3 e8 [2] e5 dd [2] cb dd [2] f4 c1 }

  condition:
    any of them
}