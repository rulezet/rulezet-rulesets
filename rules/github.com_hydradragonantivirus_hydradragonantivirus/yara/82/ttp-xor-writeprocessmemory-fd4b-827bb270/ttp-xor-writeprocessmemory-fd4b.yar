rule TTP_XOR_WriteProcessMemory_fd4b {
  strings:
    $key_fd4b = { aa 39 [2] 98 1b [2] 9e 2e [2] b0 2e [2] 8f 32 }

  condition:
    any of them
}