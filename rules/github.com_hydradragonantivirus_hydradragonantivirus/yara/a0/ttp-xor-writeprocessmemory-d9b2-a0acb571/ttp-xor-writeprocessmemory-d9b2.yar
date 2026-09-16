rule TTP_XOR_WriteProcessMemory_d9b2 {
  strings:
    $key_d9b2 = { 8e c0 [2] bc e2 [2] ba d7 [2] 94 d7 [2] ab cb }

  condition:
    any of them
}