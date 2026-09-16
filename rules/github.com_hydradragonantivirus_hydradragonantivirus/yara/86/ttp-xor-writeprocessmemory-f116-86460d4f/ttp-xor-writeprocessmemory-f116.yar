rule TTP_XOR_WriteProcessMemory_f116 {
  strings:
    $key_f116 = { a6 64 [2] 94 46 [2] 92 73 [2] bc 73 [2] 83 6f }

  condition:
    any of them
}