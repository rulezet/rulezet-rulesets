rule TTP_XOR_WriteProcessMemory_0727 {
  strings:
    $key_0727 = { 50 55 [2] 62 77 [2] 64 42 [2] 4a 42 [2] 75 5e }

  condition:
    any of them
}