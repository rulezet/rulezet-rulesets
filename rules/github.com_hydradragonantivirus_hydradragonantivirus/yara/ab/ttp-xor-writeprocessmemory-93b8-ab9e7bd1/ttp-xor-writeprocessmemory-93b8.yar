rule TTP_XOR_WriteProcessMemory_93b8 {
  strings:
    $key_93b8 = { c4 ca [2] f6 e8 [2] f0 dd [2] de dd [2] e1 c1 }

  condition:
    any of them
}