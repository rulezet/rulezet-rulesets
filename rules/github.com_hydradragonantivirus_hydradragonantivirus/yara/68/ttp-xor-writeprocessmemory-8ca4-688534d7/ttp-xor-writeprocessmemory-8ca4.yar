rule TTP_XOR_WriteProcessMemory_8ca4 {
  strings:
    $key_8ca4 = { db d6 [2] e9 f4 [2] ef c1 [2] c1 c1 [2] fe dd }

  condition:
    any of them
}