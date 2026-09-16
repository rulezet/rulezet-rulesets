rule TTP_XOR_WriteProcessMemory_1f2b {
  strings:
    $key_1f2b = { 48 59 [2] 7a 7b [2] 7c 4e [2] 52 4e [2] 6d 52 }

  condition:
    any of them
}