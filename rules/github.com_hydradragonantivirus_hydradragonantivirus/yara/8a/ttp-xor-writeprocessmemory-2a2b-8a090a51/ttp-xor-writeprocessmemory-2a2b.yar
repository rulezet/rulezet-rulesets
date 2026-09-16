rule TTP_XOR_WriteProcessMemory_2a2b {
  strings:
    $key_2a2b = { 7d 59 [2] 4f 7b [2] 49 4e [2] 67 4e [2] 58 52 }

  condition:
    any of them
}