rule TTP_XOR_WriteProcessMemory_5186 {
  strings:
    $key_5186 = { 06 f4 [2] 34 d6 [2] 32 e3 [2] 1c e3 [2] 23 ff }

  condition:
    any of them
}