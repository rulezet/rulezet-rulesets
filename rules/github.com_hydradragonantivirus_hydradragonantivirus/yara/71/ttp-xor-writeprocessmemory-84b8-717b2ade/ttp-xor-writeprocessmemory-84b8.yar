rule TTP_XOR_WriteProcessMemory_84b8 {
  strings:
    $key_84b8 = { d3 ca [2] e1 e8 [2] e7 dd [2] c9 dd [2] f6 c1 }

  condition:
    any of them
}