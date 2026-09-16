rule TTP_XOR_WriteProcessMemory_d982 {
  strings:
    $key_d982 = { 8e f0 [2] bc d2 [2] ba e7 [2] 94 e7 [2] ab fb }

  condition:
    any of them
}