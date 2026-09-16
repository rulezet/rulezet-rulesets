rule TTP_XOR_WriteProcessMemory_fd2c {
  strings:
    $key_fd2c = { aa 5e [2] 98 7c [2] 9e 49 [2] b0 49 [2] 8f 55 }

  condition:
    any of them
}