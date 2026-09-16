rule TTP_XOR_WriteProcessMemory_e440 {
  strings:
    $key_e440 = { b3 32 [2] 81 10 [2] 87 25 [2] a9 25 [2] 96 39 }

  condition:
    any of them
}