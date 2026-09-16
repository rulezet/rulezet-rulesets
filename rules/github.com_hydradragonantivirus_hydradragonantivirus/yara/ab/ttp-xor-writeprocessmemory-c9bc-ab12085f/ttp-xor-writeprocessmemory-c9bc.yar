rule TTP_XOR_WriteProcessMemory_c9bc {
  strings:
    $key_c9bc = { 9e ce [2] ac ec [2] aa d9 [2] 84 d9 [2] bb c5 }

  condition:
    any of them
}