rule TTP_XOR_WriteProcessMemory_a2b8 {
  strings:
    $key_a2b8 = { f5 ca [2] c7 e8 [2] c1 dd [2] ef dd [2] d0 c1 }

  condition:
    any of them
}