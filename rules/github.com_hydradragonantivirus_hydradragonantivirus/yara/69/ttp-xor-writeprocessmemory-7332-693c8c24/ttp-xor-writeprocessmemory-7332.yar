rule TTP_XOR_WriteProcessMemory_7332 {
  strings:
    $key_7332 = { 24 40 [2] 16 62 [2] 10 57 [2] 3e 57 [2] 01 4b }

  condition:
    any of them
}