rule TTP_XOR_WriteProcessMemory_f1cf {
  strings:
    $key_f1cf = { a6 bd [2] 94 9f [2] 92 aa [2] bc aa [2] 83 b6 }

  condition:
    any of them
}