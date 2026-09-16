rule TTP_XOR_WriteProcessMemory_5386 {
  strings:
    $key_5386 = { 04 f4 [2] 36 d6 [2] 30 e3 [2] 1e e3 [2] 21 ff }

  condition:
    any of them
}