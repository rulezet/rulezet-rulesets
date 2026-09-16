rule TTP_XOR_WriteProcessMemory_f159 {
  strings:
    $key_f159 = { a6 2b [2] 94 09 [2] 92 3c [2] bc 3c [2] 83 20 }

  condition:
    any of them
}