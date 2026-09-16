rule TTP_XOR_WriteProcessMemory_fd94 {
  strings:
    $key_fd94 = { aa e6 [2] 98 c4 [2] 9e f1 [2] b0 f1 [2] 8f ed }

  condition:
    any of them
}