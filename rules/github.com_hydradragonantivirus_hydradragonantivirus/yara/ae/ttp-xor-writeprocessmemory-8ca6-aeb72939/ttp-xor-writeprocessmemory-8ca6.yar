rule TTP_XOR_WriteProcessMemory_8ca6 {
  strings:
    $key_8ca6 = { db d4 [2] e9 f6 [2] ef c3 [2] c1 c3 [2] fe df }

  condition:
    any of them
}