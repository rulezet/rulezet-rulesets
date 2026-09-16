rule TTP_XOR_WriteProcessMemory_464e {
  strings:
    $key_464e = { 11 3c [2] 23 1e [2] 25 2b [2] 0b 2b [2] 34 37 }

  condition:
    any of them
}