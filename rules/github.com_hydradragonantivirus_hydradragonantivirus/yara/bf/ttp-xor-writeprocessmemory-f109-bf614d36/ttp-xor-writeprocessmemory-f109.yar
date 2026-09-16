rule TTP_XOR_WriteProcessMemory_f109 {
  strings:
    $key_f109 = { a6 7b [2] 94 59 [2] 92 6c [2] bc 6c [2] 83 70 }

  condition:
    any of them
}