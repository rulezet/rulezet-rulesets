rule TTP_XOR_WriteProcessMemory_92b8 {
  strings:
    $key_92b8 = { c5 ca [2] f7 e8 [2] f1 dd [2] df dd [2] e0 c1 }

  condition:
    any of them
}