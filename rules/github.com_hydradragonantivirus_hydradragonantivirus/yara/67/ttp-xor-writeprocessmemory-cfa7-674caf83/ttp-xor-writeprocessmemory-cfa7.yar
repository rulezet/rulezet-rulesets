rule TTP_XOR_WriteProcessMemory_cfa7 {
  strings:
    $key_cfa7 = { 98 d5 [2] aa f7 [2] ac c2 [2] 82 c2 [2] bd de }

  condition:
    any of them
}