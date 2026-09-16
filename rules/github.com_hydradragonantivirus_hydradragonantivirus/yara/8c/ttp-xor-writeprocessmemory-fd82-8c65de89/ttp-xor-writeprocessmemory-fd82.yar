rule TTP_XOR_WriteProcessMemory_fd82 {
  strings:
    $key_fd82 = { aa f0 [2] 98 d2 [2] 9e e7 [2] b0 e7 [2] 8f fb }

  condition:
    any of them
}