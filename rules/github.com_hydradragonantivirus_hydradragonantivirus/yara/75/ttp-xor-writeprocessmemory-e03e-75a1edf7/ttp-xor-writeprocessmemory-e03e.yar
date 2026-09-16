rule TTP_XOR_WriteProcessMemory_e03e {
  strings:
    $key_e03e = { b7 4c [2] 85 6e [2] 83 5b [2] ad 5b [2] 92 47 }

  condition:
    any of them
}