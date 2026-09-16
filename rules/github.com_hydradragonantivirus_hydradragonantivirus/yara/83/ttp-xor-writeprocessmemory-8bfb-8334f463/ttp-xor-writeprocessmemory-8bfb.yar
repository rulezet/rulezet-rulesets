rule TTP_XOR_WriteProcessMemory_8bfb {
  strings:
    $key_8bfb = { dc 89 [2] ee ab [2] e8 9e [2] c6 9e [2] f9 82 }

  condition:
    any of them
}