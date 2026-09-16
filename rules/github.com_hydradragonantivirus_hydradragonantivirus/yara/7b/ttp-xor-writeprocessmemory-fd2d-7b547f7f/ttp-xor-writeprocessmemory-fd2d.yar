rule TTP_XOR_WriteProcessMemory_fd2d {
  strings:
    $key_fd2d = { aa 5f [2] 98 7d [2] 9e 48 [2] b0 48 [2] 8f 54 }

  condition:
    any of them
}