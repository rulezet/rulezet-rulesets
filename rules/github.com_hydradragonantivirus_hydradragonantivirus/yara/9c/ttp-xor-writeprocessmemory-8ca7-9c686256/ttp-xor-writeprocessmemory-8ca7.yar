rule TTP_XOR_WriteProcessMemory_8ca7 {
  strings:
    $key_8ca7 = { db d5 [2] e9 f7 [2] ef c2 [2] c1 c2 [2] fe de }

  condition:
    any of them
}