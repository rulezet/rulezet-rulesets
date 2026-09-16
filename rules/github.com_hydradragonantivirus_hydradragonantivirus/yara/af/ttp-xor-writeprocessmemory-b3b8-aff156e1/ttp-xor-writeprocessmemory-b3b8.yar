rule TTP_XOR_WriteProcessMemory_b3b8 {
  strings:
    $key_b3b8 = { e4 ca [2] d6 e8 [2] d0 dd [2] fe dd [2] c1 c1 }

  condition:
    any of them
}