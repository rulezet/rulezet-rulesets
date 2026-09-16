rule TTP_XOR_WriteProcessMemory_974b {
  strings:
    $key_974b = { c0 39 [2] f2 1b [2] f4 2e [2] da 2e [2] e5 32 }

  condition:
    any of them
}