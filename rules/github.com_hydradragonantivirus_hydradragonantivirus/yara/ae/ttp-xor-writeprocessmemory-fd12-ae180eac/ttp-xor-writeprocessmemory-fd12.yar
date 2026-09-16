rule TTP_XOR_WriteProcessMemory_fd12 {
  strings:
    $key_fd12 = { aa 60 [2] 98 42 [2] 9e 77 [2] b0 77 [2] 8f 6b }

  condition:
    any of them
}