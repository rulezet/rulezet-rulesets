rule TTP_XOR_WriteProcessMemory_f151 {
  strings:
    $key_f151 = { a6 23 [2] 94 01 [2] 92 34 [2] bc 34 [2] 83 28 }

  condition:
    any of them
}