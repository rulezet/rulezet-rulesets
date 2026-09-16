rule TTP_XOR_WriteProcessMemory_1dbe {
  strings:
    $key_1dbe = { 4a cc [2] 78 ee [2] 7e db [2] 50 db [2] 6f c7 }

  condition:
    any of them
}