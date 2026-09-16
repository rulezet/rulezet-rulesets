rule TTP_XOR_WriteProcessMemory_7127 {
  strings:
    $key_7127 = { 26 55 [2] 14 77 [2] 12 42 [2] 3c 42 [2] 03 5e }

  condition:
    any of them
}