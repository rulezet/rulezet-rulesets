rule TTP_XOR_WriteProcessMemory_e64e {
  strings:
    $key_e64e = { b1 3c [2] 83 1e [2] 85 2b [2] ab 2b [2] 94 37 }

  condition:
    any of them
}