rule TTP_XOR_WriteProcessMemory_dedb {
  strings:
    $key_dedb = { 89 a9 [2] bb 8b [2] bd be [2] 93 be [2] ac a2 }

  condition:
    any of them
}