rule TTP_XOR_WriteProcessMemory_8c9c {
  strings:
    $key_8c9c = { db ee [2] e9 cc [2] ef f9 [2] c1 f9 [2] fe e5 }

  condition:
    any of them
}