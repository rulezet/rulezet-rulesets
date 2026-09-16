rule TTP_XOR_WriteProcessMemory_1175 {
  strings:
    $key_1175 = { 46 07 [2] 74 25 [2] 72 10 [2] 5c 10 [2] 63 0c }

  condition:
    any of them
}