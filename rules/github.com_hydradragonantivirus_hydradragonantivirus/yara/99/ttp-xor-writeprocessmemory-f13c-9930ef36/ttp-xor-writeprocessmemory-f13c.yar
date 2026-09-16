rule TTP_XOR_WriteProcessMemory_f13c {
  strings:
    $key_f13c = { a6 4e [2] 94 6c [2] 92 59 [2] bc 59 [2] 83 45 }

  condition:
    any of them
}