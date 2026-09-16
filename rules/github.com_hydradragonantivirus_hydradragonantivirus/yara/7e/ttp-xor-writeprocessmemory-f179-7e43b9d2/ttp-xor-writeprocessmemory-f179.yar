rule TTP_XOR_WriteProcessMemory_f179 {
  strings:
    $key_f179 = { a6 0b [2] 94 29 [2] 92 1c [2] bc 1c [2] 83 00 }

  condition:
    any of them
}