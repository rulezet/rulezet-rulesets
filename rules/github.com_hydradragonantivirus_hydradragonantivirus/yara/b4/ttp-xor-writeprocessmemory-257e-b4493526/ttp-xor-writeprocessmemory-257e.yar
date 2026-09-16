rule TTP_XOR_WriteProcessMemory_257e {
  strings:
    $key_257e = { 72 0c [2] 40 2e [2] 46 1b [2] 68 1b [2] 57 07 }

  condition:
    any of them
}