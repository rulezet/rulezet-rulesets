rule TTP_XOR_WriteProcessMemory_cfac {
  strings:
    $key_cfac = { 98 de [2] aa fc [2] ac c9 [2] 82 c9 [2] bd d5 }

  condition:
    any of them
}