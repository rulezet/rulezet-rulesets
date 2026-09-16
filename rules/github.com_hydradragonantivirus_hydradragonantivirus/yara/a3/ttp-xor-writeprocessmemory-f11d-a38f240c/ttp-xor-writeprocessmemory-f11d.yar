rule TTP_XOR_WriteProcessMemory_f11d {
  strings:
    $key_f11d = { a6 6f [2] 94 4d [2] 92 78 [2] bc 78 [2] 83 64 }

  condition:
    any of them
}