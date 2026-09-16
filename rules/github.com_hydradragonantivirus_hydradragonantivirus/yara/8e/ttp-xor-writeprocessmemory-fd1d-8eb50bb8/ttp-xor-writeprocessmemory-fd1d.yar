rule TTP_XOR_WriteProcessMemory_fd1d {
  strings:
    $key_fd1d = { aa 6f [2] 98 4d [2] 9e 78 [2] b0 78 [2] 8f 64 }

  condition:
    any of them
}