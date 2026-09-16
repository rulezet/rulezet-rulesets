rule TTP_XOR_WriteProcessMemory_cfb4 {
  strings:
    $key_cfb4 = { 98 c6 [2] aa e4 [2] ac d1 [2] 82 d1 [2] bd cd }

  condition:
    any of them
}