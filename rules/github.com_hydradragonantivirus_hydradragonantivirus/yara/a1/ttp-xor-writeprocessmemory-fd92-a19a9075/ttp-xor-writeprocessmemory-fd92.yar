rule TTP_XOR_WriteProcessMemory_fd92 {
  strings:
    $key_fd92 = { aa e0 [2] 98 c2 [2] 9e f7 [2] b0 f7 [2] 8f eb }

  condition:
    any of them
}