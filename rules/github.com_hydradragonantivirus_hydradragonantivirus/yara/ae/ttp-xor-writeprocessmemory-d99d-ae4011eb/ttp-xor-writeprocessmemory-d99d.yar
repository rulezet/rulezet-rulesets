rule TTP_XOR_WriteProcessMemory_d99d {
  strings:
    $key_d99d = { 8e ef [2] bc cd [2] ba f8 [2] 94 f8 [2] ab e4 }

  condition:
    any of them
}