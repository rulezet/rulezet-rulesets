rule TTP_XOR_WriteProcessMemory_7382 {
  strings:
    $key_7382 = { 24 f0 [2] 16 d2 [2] 10 e7 [2] 3e e7 [2] 01 fb }

  condition:
    any of them
}