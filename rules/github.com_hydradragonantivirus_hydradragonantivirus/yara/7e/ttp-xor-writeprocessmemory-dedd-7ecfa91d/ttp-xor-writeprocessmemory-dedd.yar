rule TTP_XOR_WriteProcessMemory_dedd {
  strings:
    $key_dedd = { 89 af [2] bb 8d [2] bd b8 [2] 93 b8 [2] ac a4 }

  condition:
    any of them
}