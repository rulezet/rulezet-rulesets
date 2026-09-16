rule TTP_XOR_WriteProcessMemory_ef4b {
  strings:
    $key_ef4b = { b8 39 [2] 8a 1b [2] 8c 2e [2] a2 2e [2] 9d 32 }

  condition:
    any of them
}