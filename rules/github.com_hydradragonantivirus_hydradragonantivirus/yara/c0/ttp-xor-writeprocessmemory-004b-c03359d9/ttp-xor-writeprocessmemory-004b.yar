rule TTP_XOR_WriteProcessMemory_004b {
  strings:
    $key_004b = { 57 39 [2] 65 1b [2] 63 2e [2] 4d 2e [2] 72 32 }

  condition:
    any of them
}