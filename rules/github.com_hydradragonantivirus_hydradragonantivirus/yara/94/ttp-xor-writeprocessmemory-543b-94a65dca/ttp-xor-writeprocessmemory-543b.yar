rule TTP_XOR_WriteProcessMemory_543b {
  strings:
    $key_543b = { 03 49 [2] 31 6b [2] 37 5e [2] 19 5e [2] 26 42 }

  condition:
    any of them
}