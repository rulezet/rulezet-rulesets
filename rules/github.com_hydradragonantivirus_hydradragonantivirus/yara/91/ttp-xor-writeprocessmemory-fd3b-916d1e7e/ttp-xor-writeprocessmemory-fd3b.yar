rule TTP_XOR_WriteProcessMemory_fd3b {
  strings:
    $key_fd3b = { aa 49 [2] 98 6b [2] 9e 5e [2] b0 5e [2] 8f 42 }

  condition:
    any of them
}