rule TTP_XOR_WriteProcessMemory_7d57 {
  strings:
    $key_7d57 = { 2a 25 [2] 18 07 [2] 1e 32 [2] 30 32 [2] 0f 2e }

  condition:
    any of them
}