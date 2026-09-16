rule TTP_XOR_WriteProcessMemory_1382 {
  strings:
    $key_1382 = { 44 f0 [2] 76 d2 [2] 70 e7 [2] 5e e7 [2] 61 fb }

  condition:
    any of them
}