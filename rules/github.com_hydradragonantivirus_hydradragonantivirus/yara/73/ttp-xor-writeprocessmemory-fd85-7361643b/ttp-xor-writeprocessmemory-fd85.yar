rule TTP_XOR_WriteProcessMemory_fd85 {
  strings:
    $key_fd85 = { aa f7 [2] 98 d5 [2] 9e e0 [2] b0 e0 [2] 8f fc }

  condition:
    any of them
}