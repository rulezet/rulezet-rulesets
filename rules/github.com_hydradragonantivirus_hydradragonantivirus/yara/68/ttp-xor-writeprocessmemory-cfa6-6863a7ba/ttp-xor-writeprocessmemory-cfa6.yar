rule TTP_XOR_WriteProcessMemory_cfa6 {
  strings:
    $key_cfa6 = { 98 d4 [2] aa f6 [2] ac c3 [2] 82 c3 [2] bd df }

  condition:
    any of them
}