rule TTP_XOR_WriteProcessMemory_e72b {
  strings:
    $key_e72b = { b0 59 [2] 82 7b [2] 84 4e [2] aa 4e [2] 95 52 }

  condition:
    any of them
}