rule TTP_XOR_WriteProcessMemory_7317 {
  strings:
    $key_7317 = { 24 65 [2] 16 47 [2] 10 72 [2] 3e 72 [2] 01 6e }

  condition:
    any of them
}