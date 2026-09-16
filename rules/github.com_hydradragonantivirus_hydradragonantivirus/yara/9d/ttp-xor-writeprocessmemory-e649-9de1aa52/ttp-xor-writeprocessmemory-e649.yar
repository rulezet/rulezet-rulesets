rule TTP_XOR_WriteProcessMemory_e649 {
  strings:
    $key_e649 = { b1 3b [2] 83 19 [2] 85 2c [2] ab 2c [2] 94 30 }

  condition:
    any of them
}