rule TTP_XOR_WriteProcessMemory_765b {
  strings:
    $key_765b = { 21 29 [2] 13 0b [2] 15 3e [2] 3b 3e [2] 04 22 }

  condition:
    any of them
}