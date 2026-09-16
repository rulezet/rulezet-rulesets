rule TTP_XOR_WriteProcessMemory_fd46 {
  strings:
    $key_fd46 = { aa 34 [2] 98 16 [2] 9e 23 [2] b0 23 [2] 8f 3f }

  condition:
    any of them
}