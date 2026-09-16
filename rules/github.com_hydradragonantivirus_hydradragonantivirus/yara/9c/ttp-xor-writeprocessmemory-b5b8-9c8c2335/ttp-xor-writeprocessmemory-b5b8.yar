rule TTP_XOR_WriteProcessMemory_b5b8 {
  strings:
    $key_b5b8 = { e2 ca [2] d0 e8 [2] d6 dd [2] f8 dd [2] c7 c1 }

  condition:
    any of them
}