rule TTP_XOR_WriteProcessMemory_4b77 {
  strings:
    $key_4b77 = { 1c 05 [2] 2e 27 [2] 28 12 [2] 06 12 [2] 39 0e }

  condition:
    any of them
}