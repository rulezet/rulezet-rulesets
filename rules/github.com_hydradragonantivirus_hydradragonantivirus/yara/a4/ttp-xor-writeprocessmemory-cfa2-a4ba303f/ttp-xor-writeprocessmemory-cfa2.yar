rule TTP_XOR_WriteProcessMemory_cfa2 {
  strings:
    $key_cfa2 = { 98 d0 [2] aa f2 [2] ac c7 [2] 82 c7 [2] bd db }

  condition:
    any of them
}