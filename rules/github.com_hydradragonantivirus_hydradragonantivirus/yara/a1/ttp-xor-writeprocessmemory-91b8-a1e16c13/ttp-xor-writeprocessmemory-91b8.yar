rule TTP_XOR_WriteProcessMemory_91b8 {
  strings:
    $key_91b8 = { c6 ca [2] f4 e8 [2] f2 dd [2] dc dd [2] e3 c1 }

  condition:
    any of them
}