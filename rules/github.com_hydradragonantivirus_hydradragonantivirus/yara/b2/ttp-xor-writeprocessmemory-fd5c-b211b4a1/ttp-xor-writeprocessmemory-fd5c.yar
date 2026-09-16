rule TTP_XOR_WriteProcessMemory_fd5c {
  strings:
    $key_fd5c = { aa 2e [2] 98 0c [2] 9e 39 [2] b0 39 [2] 8f 25 }

  condition:
    any of them
}