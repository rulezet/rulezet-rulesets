rule TTP_XOR_WriteProcessMemory_0dbe {
  strings:
    $key_0dbe = { 5a cc [2] 68 ee [2] 6e db [2] 40 db [2] 7f c7 }

  condition:
    any of them
}