rule TTP_XOR_WriteProcessMemory_83b8 {
  strings:
    $key_83b8 = { d4 ca [2] e6 e8 [2] e0 dd [2] ce dd [2] f1 c1 }

  condition:
    any of them
}