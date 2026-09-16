rule TTP_XOR_WriteProcessMemory_d9d3 {
  strings:
    $key_d9d3 = { 8e a1 [2] bc 83 [2] ba b6 [2] 94 b6 [2] ab aa }

  condition:
    any of them
}