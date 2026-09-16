rule TTP_XOR_WriteProcessMemory_fd55 {
  strings:
    $key_fd55 = { aa 27 [2] 98 05 [2] 9e 30 [2] b0 30 [2] 8f 2c }

  condition:
    any of them
}