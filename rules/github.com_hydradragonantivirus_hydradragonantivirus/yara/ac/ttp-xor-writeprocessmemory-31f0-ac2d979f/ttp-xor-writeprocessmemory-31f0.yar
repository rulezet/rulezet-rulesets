rule TTP_XOR_WriteProcessMemory_31f0 {
  strings:
    $key_31f0 = { 66 82 [2] 54 a0 [2] 52 95 [2] 7c 95 [2] 43 89 }

  condition:
    any of them
}