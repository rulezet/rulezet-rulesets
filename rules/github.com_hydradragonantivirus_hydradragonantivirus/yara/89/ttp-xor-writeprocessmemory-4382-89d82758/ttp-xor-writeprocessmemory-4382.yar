rule TTP_XOR_WriteProcessMemory_4382 {
  strings:
    $key_4382 = { 14 f0 [2] 26 d2 [2] 20 e7 [2] 0e e7 [2] 31 fb }

  condition:
    any of them
}