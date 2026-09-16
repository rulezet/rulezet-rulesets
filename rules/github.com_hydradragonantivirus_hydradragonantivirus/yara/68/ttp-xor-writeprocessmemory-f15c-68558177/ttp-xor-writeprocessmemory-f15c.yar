rule TTP_XOR_WriteProcessMemory_f15c {
  strings:
    $key_f15c = { a6 2e [2] 94 0c [2] 92 39 [2] bc 39 [2] 83 25 }

  condition:
    any of them
}