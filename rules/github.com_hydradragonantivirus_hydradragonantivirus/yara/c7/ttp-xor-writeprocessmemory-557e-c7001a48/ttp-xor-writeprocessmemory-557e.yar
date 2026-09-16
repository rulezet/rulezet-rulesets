rule TTP_XOR_WriteProcessMemory_557e {
  strings:
    $key_557e = { 02 0c [2] 30 2e [2] 36 1b [2] 18 1b [2] 27 07 }

  condition:
    any of them
}