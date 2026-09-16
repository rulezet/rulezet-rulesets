rule TTP_XOR_WriteProcessMemory_695b {
  strings:
    $key_695b = { 3e 29 [2] 0c 0b [2] 0a 3e [2] 24 3e [2] 1b 22 }

  condition:
    any of them
}