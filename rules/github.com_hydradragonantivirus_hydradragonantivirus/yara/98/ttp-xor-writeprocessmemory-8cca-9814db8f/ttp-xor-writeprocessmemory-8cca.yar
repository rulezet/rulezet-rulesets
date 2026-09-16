rule TTP_XOR_WriteProcessMemory_8cca {
  strings:
    $key_8cca = { db b8 [2] e9 9a [2] ef af [2] c1 af [2] fe b3 }

  condition:
    any of them
}