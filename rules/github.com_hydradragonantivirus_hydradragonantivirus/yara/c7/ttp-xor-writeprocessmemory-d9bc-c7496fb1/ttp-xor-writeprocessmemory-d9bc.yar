rule TTP_XOR_WriteProcessMemory_d9bc {
  strings:
    $key_d9bc = { 8e ce [2] bc ec [2] ba d9 [2] 94 d9 [2] ab c5 }

  condition:
    any of them
}