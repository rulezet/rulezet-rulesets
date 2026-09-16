rule TTP_XOR_WriteProcessMemory_064b {
  strings:
    $key_064b = { 51 39 [2] 63 1b [2] 65 2e [2] 4b 2e [2] 74 32 }

  condition:
    any of them
}