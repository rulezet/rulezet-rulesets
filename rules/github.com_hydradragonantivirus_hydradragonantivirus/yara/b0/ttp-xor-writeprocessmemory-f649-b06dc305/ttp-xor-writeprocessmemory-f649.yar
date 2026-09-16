rule TTP_XOR_WriteProcessMemory_f649 {
  strings:
    $key_f649 = { a1 3b [2] 93 19 [2] 95 2c [2] bb 2c [2] 84 30 }

  condition:
    any of them
}