rule TTP_XOR_WriteProcessMemory_c9be {
  strings:
    $key_c9be = { 9e cc [2] ac ee [2] aa db [2] 84 db [2] bb c7 }

  condition:
    any of them
}