rule TTP_XOR_WriteProcessMemory_233b {
  strings:
    $key_233b = { 74 49 [2] 46 6b [2] 40 5e [2] 6e 5e [2] 51 42 }

  condition:
    any of them
}