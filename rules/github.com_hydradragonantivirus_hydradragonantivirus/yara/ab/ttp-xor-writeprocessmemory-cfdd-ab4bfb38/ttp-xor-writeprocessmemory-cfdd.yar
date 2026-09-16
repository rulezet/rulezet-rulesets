rule TTP_XOR_WriteProcessMemory_cfdd {
  strings:
    $key_cfdd = { 98 af [2] aa 8d [2] ac b8 [2] 82 b8 [2] bd a4 }

  condition:
    any of them
}