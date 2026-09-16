rule TTP_XOR_WriteProcessMemory_a6b8 {
  strings:
    $key_a6b8 = { f1 ca [2] c3 e8 [2] c5 dd [2] eb dd [2] d4 c1 }

  condition:
    any of them
}