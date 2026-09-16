rule TTP_XOR_WriteProcessMemory_e482 {
  strings:
    $key_e482 = { b3 f0 [2] 81 d2 [2] 87 e7 [2] a9 e7 [2] 96 fb }

  condition:
    any of them
}