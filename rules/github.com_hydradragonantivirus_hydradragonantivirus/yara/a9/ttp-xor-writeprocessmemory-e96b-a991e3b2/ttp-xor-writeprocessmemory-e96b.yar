rule TTP_XOR_WriteProcessMemory_e96b {
  strings:
    $key_e96b = { be 19 [2] 8c 3b [2] 8a 0e [2] a4 0e [2] 9b 12 }

  condition:
    any of them
}