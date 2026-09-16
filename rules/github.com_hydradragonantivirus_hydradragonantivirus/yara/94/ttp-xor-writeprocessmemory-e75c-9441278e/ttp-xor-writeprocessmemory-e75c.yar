rule TTP_XOR_WriteProcessMemory_e75c {
  strings:
    $key_e75c = { b0 2e [2] 82 0c [2] 84 39 [2] aa 39 [2] 95 25 }

  condition:
    any of them
}