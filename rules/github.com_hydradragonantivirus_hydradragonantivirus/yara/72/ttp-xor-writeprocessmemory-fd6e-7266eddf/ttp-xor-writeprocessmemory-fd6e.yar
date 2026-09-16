rule TTP_XOR_WriteProcessMemory_fd6e {
  strings:
    $key_fd6e = { aa 1c [2] 98 3e [2] 9e 0b [2] b0 0b [2] 8f 17 }

  condition:
    any of them
}