rule TTP_XOR_WriteProcessMemory_3482 {
  strings:
    $key_3482 = { 63 f0 [2] 51 d2 [2] 57 e7 [2] 79 e7 [2] 46 fb }

  condition:
    any of them
}