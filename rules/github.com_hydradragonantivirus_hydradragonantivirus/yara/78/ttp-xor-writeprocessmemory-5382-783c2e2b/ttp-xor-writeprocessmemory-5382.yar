rule TTP_XOR_WriteProcessMemory_5382 {
  strings:
    $key_5382 = { 04 f0 [2] 36 d2 [2] 30 e7 [2] 1e e7 [2] 21 fb }

  condition:
    any of them
}