rule TTP_XOR_WriteProcessMemory_874b {
  strings:
    $key_874b = { d0 39 [2] e2 1b [2] e4 2e [2] ca 2e [2] f5 32 }

  condition:
    any of them
}