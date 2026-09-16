rule TTP_XOR_WriteProcessMemory_f1d3 {
  strings:
    $key_f1d3 = { a6 a1 [2] 94 83 [2] 92 b6 [2] bc b6 [2] 83 aa }

  condition:
    any of them
}