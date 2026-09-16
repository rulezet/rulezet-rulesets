rule TTP_XOR_WriteProcessMemory_1767 {
  strings:
    $key_1767 = { 40 15 [2] 72 37 [2] 74 02 [2] 5a 02 [2] 65 1e }

  condition:
    any of them
}