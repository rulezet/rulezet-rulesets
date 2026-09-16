rule TTP_XOR_WriteProcessMemory_323b {
  strings:
    $key_323b = { 65 49 [2] 57 6b [2] 51 5e [2] 7f 5e [2] 40 42 }

  condition:
    any of them
}