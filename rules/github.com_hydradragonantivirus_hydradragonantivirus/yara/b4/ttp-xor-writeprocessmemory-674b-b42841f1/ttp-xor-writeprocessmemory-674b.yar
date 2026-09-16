rule TTP_XOR_WriteProcessMemory_674b {
  strings:
    $key_674b = { 30 39 [2] 02 1b [2] 04 2e [2] 2a 2e [2] 15 32 }

  condition:
    any of them
}