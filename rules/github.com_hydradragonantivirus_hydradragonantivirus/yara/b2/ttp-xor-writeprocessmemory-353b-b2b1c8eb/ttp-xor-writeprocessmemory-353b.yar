rule TTP_XOR_WriteProcessMemory_353b {
  strings:
    $key_353b = { 62 49 [2] 50 6b [2] 56 5e [2] 78 5e [2] 47 42 }

  condition:
    any of them
}