rule TTP_XOR_WriteProcessMemory_514b {
  strings:
    $key_514b = { 06 39 [2] 34 1b [2] 32 2e [2] 1c 2e [2] 23 32 }

  condition:
    any of them
}