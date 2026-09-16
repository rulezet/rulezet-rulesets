rule TTP_XOR_WriteProcessMemory_82b8 {
  strings:
    $key_82b8 = { d5 ca [2] e7 e8 [2] e1 dd [2] cf dd [2] f0 c1 }

  condition:
    any of them
}