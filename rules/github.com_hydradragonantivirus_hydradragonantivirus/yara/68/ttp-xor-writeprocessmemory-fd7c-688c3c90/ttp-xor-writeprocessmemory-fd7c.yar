rule TTP_XOR_WriteProcessMemory_fd7c {
  strings:
    $key_fd7c = { aa 0e [2] 98 2c [2] 9e 19 [2] b0 19 [2] 8f 05 }

  condition:
    any of them
}