rule TTP_XOR_WriteProcessMemory_cfdb {
  strings:
    $key_cfdb = { 98 a9 [2] aa 8b [2] ac be [2] 82 be [2] bd a2 }

  condition:
    any of them
}