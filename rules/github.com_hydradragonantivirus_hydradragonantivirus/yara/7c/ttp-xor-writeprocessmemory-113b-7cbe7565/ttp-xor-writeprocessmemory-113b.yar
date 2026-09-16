rule TTP_XOR_WriteProcessMemory_113b {
  strings:
    $key_113b = { 46 49 [2] 74 6b [2] 72 5e [2] 5c 5e [2] 63 42 }

  condition:
    any of them
}