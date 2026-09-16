rule TTP_XOR_WriteProcessMemory_fd52 {
  strings:
    $key_fd52 = { aa 20 [2] 98 02 [2] 9e 37 [2] b0 37 [2] 8f 2b }

  condition:
    any of them
}