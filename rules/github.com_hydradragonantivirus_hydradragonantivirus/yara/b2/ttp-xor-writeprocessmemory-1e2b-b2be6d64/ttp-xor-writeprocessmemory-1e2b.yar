rule TTP_XOR_WriteProcessMemory_1e2b {
  strings:
    $key_1e2b = { 49 59 [2] 7b 7b [2] 7d 4e [2] 53 4e [2] 6c 52 }

  condition:
    any of them
}