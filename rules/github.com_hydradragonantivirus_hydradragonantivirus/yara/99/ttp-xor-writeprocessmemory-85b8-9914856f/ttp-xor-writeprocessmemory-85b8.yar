rule TTP_XOR_WriteProcessMemory_85b8 {
  strings:
    $key_85b8 = { d2 ca [2] e0 e8 [2] e6 dd [2] c8 dd [2] f7 c1 }

  condition:
    any of them
}