rule TTP_XOR_WriteProcessMemory_2582 {
  strings:
    $key_2582 = { 72 f0 [2] 40 d2 [2] 46 e7 [2] 68 e7 [2] 57 fb }

  condition:
    any of them
}