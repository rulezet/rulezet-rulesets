rule TTP_XOR_WriteProcessMemory_7d77 {
  strings:
    $key_7d77 = { 2a 05 [2] 18 27 [2] 1e 12 [2] 30 12 [2] 0f 0e }

  condition:
    any of them
}