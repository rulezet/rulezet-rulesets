rule TTP_XOR_WriteProcessMemory_e62b {
  strings:
    $key_e62b = { b1 59 [2] 83 7b [2] 85 4e [2] ab 4e [2] 94 52 }

  condition:
    any of them
}