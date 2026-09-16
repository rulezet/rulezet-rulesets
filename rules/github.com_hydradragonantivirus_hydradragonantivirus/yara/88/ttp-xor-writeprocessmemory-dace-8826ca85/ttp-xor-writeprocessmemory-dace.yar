rule TTP_XOR_WriteProcessMemory_dace {
  strings:
    $key_dace = { 8d bc [2] bf 9e [2] b9 ab [2] 97 ab [2] a8 b7 }

  condition:
    any of them
}