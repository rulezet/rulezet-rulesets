rule TTP_XOR_WriteProcessMemory_e019 {
  strings:
    $key_e019 = { b7 6b [2] 85 49 [2] 83 7c [2] ad 7c [2] 92 60 }

  condition:
    any of them
}