rule TTP_XOR_WriteProcessMemory_2a5b {
  strings:
    $key_2a5b = { 7d 29 [2] 4f 0b [2] 49 3e [2] 67 3e [2] 58 22 }

  condition:
    any of them
}