rule TTP_XOR_WriteProcessMemory_736b {
  strings:
    $key_736b = { 24 19 [2] 16 3b [2] 10 0e [2] 3e 0e [2] 01 12 }

  condition:
    any of them
}