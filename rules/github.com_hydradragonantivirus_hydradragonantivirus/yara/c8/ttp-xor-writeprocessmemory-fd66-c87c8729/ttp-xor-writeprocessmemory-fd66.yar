rule TTP_XOR_WriteProcessMemory_fd66 {
  strings:
    $key_fd66 = { aa 14 [2] 98 36 [2] 9e 03 [2] b0 03 [2] 8f 1f }

  condition:
    any of them
}