rule TTP_XOR_WriteProcessMemory_e07e {
  strings:
    $key_e07e = { b7 0c [2] 85 2e [2] 83 1b [2] ad 1b [2] 92 07 }

  condition:
    any of them
}