rule TTP_XOR_WriteProcessMemory_b4b8 {
  strings:
    $key_b4b8 = { e3 ca [2] d1 e8 [2] d7 dd [2] f9 dd [2] c6 c1 }

  condition:
    any of them
}