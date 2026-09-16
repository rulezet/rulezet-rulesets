rule TTP_XOR_WriteProcessMemory_e069 {
  strings:
    $key_e069 = { b7 1b [2] 85 39 [2] 83 0c [2] ad 0c [2] 92 10 }

  condition:
    any of them
}