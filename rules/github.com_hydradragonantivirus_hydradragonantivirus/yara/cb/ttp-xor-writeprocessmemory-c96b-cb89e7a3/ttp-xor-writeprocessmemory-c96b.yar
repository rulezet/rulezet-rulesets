rule TTP_XOR_WriteProcessMemory_c96b {
  strings:
    $key_c96b = { 9e 19 [2] ac 3b [2] aa 0e [2] 84 0e [2] bb 12 }

  condition:
    any of them
}