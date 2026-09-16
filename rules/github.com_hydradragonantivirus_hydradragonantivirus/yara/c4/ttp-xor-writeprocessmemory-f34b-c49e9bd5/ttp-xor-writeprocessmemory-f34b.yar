rule TTP_XOR_WriteProcessMemory_f34b {
  strings:
    $key_f34b = { a4 39 [2] 96 1b [2] 90 2e [2] be 2e [2] 81 32 }

  condition:
    any of them
}