rule TTP_XOR_WriteProcessMemory_e029 {
  strings:
    $key_e029 = { b7 5b [2] 85 79 [2] 83 4c [2] ad 4c [2] 92 50 }

  condition:
    any of them
}