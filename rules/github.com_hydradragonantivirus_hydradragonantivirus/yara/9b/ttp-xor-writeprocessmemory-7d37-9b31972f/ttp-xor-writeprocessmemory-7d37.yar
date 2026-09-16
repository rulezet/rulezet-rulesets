rule TTP_XOR_WriteProcessMemory_7d37 {
  strings:
    $key_7d37 = { 2a 45 [2] 18 67 [2] 1e 52 [2] 30 52 [2] 0f 4e }

  condition:
    any of them
}