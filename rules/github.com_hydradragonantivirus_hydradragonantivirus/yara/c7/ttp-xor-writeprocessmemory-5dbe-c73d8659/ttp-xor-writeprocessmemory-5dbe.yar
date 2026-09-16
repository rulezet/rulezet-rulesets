rule TTP_XOR_WriteProcessMemory_5dbe {
  strings:
    $key_5dbe = { 0a cc [2] 38 ee [2] 3e db [2] 10 db [2] 2f c7 }

  condition:
    any of them
}