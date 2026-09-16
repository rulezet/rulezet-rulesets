rule TTP_XOR_WriteProcessMemory_464b {
  strings:
    $key_464b = { 11 39 [2] 23 1b [2] 25 2e [2] 0b 2e [2] 34 32 }

  condition:
    any of them
}