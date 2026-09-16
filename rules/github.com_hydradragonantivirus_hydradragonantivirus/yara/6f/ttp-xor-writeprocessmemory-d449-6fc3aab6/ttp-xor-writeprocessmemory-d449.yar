rule TTP_XOR_WriteProcessMemory_d449 {
  strings:
    $key_d449 = { 83 3b [2] b1 19 [2] b7 2c [2] 99 2c [2] a6 30 }

  condition:
    any of them
}