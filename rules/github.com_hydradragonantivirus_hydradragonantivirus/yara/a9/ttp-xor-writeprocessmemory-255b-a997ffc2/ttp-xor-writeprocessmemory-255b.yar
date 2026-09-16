rule TTP_XOR_WriteProcessMemory_255b {
  strings:
    $key_255b = { 72 29 [2] 40 0b [2] 46 3e [2] 68 3e [2] 57 22 }

  condition:
    any of them
}