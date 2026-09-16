rule TTP_XOR_WriteProcessMemory_fd3e {
  strings:
    $key_fd3e = { aa 4c [2] 98 6e [2] 9e 5b [2] b0 5b [2] 8f 47 }

  condition:
    any of them
}