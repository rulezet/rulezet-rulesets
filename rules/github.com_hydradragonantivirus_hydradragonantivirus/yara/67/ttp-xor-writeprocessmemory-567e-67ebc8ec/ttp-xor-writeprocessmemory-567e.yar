rule TTP_XOR_WriteProcessMemory_567e {
  strings:
    $key_567e = { 01 0c [2] 33 2e [2] 35 1b [2] 1b 1b [2] 24 07 }

  condition:
    any of them
}