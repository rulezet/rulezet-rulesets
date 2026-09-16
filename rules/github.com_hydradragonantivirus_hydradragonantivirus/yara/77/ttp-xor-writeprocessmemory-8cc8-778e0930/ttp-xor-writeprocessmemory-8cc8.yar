rule TTP_XOR_WriteProcessMemory_8cc8 {
  strings:
    $key_8cc8 = { db ba [2] e9 98 [2] ef ad [2] c1 ad [2] fe b1 }

  condition:
    any of them
}