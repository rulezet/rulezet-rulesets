rule TTP_XOR_WriteProcessMemory_307e {
  strings:
    $key_307e = { 67 0c [2] 55 2e [2] 53 1b [2] 7d 1b [2] 42 07 }

  condition:
    any of them
}