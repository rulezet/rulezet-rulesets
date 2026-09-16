rule TTP_XOR_WriteProcessMemory_247e {
  strings:
    $key_247e = { 73 0c [2] 41 2e [2] 47 1b [2] 69 1b [2] 56 07 }

  condition:
    any of them
}