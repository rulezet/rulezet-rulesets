rule TTP_XOR_WriteProcessMemory_e049 {
  strings:
    $key_e049 = { b7 3b [2] 85 19 [2] 83 2c [2] ad 2c [2] 92 30 }

  condition:
    any of them
}