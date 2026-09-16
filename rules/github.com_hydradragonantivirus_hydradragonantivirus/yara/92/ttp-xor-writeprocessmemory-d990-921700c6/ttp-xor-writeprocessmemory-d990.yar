rule TTP_XOR_WriteProcessMemory_d990 {
  strings:
    $key_d990 = { 8e e2 [2] bc c0 [2] ba f5 [2] 94 f5 [2] ab e9 }

  condition:
    any of them
}