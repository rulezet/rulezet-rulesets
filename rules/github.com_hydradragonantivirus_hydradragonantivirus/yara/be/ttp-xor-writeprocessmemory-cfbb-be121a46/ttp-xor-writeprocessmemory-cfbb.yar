rule TTP_XOR_WriteProcessMemory_cfbb {
  strings:
    $key_cfbb = { 98 c9 [2] aa eb [2] ac de [2] 82 de [2] bd c2 }

  condition:
    any of them
}