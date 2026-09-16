rule TTP_XOR_WriteProcessMemory_fd2b {
  strings:
    $key_fd2b = { aa 59 [2] 98 7b [2] 9e 4e [2] b0 4e [2] 8f 52 }

  condition:
    any of them
}