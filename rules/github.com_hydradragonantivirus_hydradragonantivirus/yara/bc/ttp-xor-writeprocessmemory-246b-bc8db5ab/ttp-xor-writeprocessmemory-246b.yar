rule TTP_XOR_WriteProcessMemory_246b {
  strings:
    $key_246b = { 73 19 [2] 41 3b [2] 47 0e [2] 69 0e [2] 56 12 }

  condition:
    any of them
}