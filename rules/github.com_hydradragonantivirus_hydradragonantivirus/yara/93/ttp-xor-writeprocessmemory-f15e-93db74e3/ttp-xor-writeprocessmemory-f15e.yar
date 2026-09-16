rule TTP_XOR_WriteProcessMemory_f15e {
  strings:
    $key_f15e = { a6 2c [2] 94 0e [2] 92 3b [2] bc 3b [2] 83 27 }

  condition:
    any of them
}