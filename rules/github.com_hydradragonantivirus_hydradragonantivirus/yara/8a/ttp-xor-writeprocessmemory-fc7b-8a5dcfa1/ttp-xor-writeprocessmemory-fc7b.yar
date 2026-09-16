rule TTP_XOR_WriteProcessMemory_fc7b {
  strings:
    $key_fc7b = { ab 09 [2] 99 2b [2] 9f 1e [2] b1 1e [2] 8e 02 }

  condition:
    any of them
}