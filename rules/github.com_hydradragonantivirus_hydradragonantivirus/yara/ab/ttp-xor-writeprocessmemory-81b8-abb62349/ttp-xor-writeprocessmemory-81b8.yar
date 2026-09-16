rule TTP_XOR_WriteProcessMemory_81b8 {
  strings:
    $key_81b8 = { d6 ca [2] e4 e8 [2] e2 dd [2] cc dd [2] f3 c1 }

  condition:
    any of them
}