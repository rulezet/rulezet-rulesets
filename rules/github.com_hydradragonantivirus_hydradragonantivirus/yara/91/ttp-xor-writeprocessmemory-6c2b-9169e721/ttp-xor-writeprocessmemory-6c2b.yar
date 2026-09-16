rule TTP_XOR_WriteProcessMemory_6c2b {
  strings:
    $key_6c2b = { 3b 59 [2] 09 7b [2] 0f 4e [2] 21 4e [2] 1e 52 }

  condition:
    any of them
}