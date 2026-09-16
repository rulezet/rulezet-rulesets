rule TTP_XOR_WriteProcessMemory_7373 {
  strings:
    $key_7373 = { 24 01 [2] 16 23 [2] 10 16 [2] 3e 16 [2] 01 0a }

  condition:
    any of them
}