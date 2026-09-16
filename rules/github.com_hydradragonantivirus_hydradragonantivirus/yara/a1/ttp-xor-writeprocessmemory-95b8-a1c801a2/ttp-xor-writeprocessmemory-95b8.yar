rule TTP_XOR_WriteProcessMemory_95b8 {
  strings:
    $key_95b8 = { c2 ca [2] f0 e8 [2] f6 dd [2] d8 dd [2] e7 c1 }

  condition:
    any of them
}