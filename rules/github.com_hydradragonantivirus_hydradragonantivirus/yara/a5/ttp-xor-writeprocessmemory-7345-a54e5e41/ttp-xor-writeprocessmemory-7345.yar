rule TTP_XOR_WriteProcessMemory_7345 {
  strings:
    $key_7345 = { 24 37 [2] 16 15 [2] 10 20 [2] 3e 20 [2] 01 3c }

  condition:
    any of them
}