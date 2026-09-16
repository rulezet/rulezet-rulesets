rule TTP_XOR_WriteProcessMemory_200b {
  strings:
    $key_200b = { 77 79 [2] 45 5b [2] 43 6e [2] 6d 6e [2] 52 72 }

  condition:
    any of them
}