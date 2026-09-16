rule TTP_XOR_WriteProcessMemory_3327 {
  strings:
    $key_3327 = { 64 55 [2] 56 77 [2] 50 42 [2] 7e 42 [2] 41 5e }

  condition:
    any of them
}