rule TTP_XOR_WriteProcessMemory_e02c {
  strings:
    $key_e02c = { b7 5e [2] 85 7c [2] 83 49 [2] ad 49 [2] 92 55 }

  condition:
    any of them
}