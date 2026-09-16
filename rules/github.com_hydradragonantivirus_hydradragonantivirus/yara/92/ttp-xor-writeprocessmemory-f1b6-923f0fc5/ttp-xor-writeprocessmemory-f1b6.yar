rule TTP_XOR_WriteProcessMemory_f1b6 {
  strings:
    $key_f1b6 = { a6 c4 [2] 94 e6 [2] 92 d3 [2] bc d3 [2] 83 cf }

  condition:
    any of them
}