rule TTP_XOR_WriteProcessMemory_e62e {
  strings:
    $key_e62e = { b1 5c [2] 83 7e [2] 85 4b [2] ab 4b [2] 94 57 }

  condition:
    any of them
}