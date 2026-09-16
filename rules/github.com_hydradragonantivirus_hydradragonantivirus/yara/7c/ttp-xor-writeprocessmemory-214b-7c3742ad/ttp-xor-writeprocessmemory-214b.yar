rule TTP_XOR_WriteProcessMemory_214b {
  strings:
    $key_214b = { 76 39 [2] 44 1b [2] 42 2e [2] 6c 2e [2] 53 32 }

  condition:
    any of them
}