rule TTP_XOR_WriteProcessMemory_e66c {
  strings:
    $key_e66c = { b1 1e [2] 83 3c [2] 85 09 [2] ab 09 [2] 94 15 }

  condition:
    any of them
}