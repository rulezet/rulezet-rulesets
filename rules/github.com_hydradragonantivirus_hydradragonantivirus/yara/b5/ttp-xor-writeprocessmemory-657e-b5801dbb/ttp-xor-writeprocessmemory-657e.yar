rule TTP_XOR_WriteProcessMemory_657e {
  strings:
    $key_657e = { 32 0c [2] 00 2e [2] 06 1b [2] 28 1b [2] 17 07 }

  condition:
    any of them
}