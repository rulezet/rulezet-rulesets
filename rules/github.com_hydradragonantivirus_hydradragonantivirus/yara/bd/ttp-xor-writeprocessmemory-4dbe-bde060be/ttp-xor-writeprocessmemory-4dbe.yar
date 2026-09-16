rule TTP_XOR_WriteProcessMemory_4dbe {
  strings:
    $key_4dbe = { 1a cc [2] 28 ee [2] 2e db [2] 00 db [2] 3f c7 }

  condition:
    any of them
}