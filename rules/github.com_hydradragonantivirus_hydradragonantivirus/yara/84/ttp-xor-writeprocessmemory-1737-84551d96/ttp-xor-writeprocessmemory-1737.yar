rule TTP_XOR_WriteProcessMemory_1737 {
  strings:
    $key_1737 = { 40 45 [2] 72 67 [2] 74 52 [2] 5a 52 [2] 65 4e }

  condition:
    any of them
}