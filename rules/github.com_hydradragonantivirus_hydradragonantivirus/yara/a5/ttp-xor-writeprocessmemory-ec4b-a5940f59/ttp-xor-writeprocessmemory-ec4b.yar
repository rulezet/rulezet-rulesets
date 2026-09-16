rule TTP_XOR_WriteProcessMemory_ec4b {
  strings:
    $key_ec4b = { bb 39 [2] 89 1b [2] 8f 2e [2] a1 2e [2] 9e 32 }

  condition:
    any of them
}