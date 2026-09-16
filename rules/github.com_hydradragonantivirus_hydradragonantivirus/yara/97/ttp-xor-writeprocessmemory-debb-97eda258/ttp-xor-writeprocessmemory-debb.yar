rule TTP_XOR_WriteProcessMemory_debb {
  strings:
    $key_debb = { 89 c9 [2] bb eb [2] bd de [2] 93 de [2] ac c2 }

  condition:
    any of them
}