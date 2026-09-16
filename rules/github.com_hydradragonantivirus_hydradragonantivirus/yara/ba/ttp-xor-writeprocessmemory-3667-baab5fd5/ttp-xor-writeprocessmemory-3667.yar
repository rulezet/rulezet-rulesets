rule TTP_XOR_WriteProcessMemory_3667 {
  strings:
    $key_3667 = { 61 15 [2] 53 37 [2] 55 02 [2] 7b 02 [2] 44 1e }

  condition:
    any of them
}