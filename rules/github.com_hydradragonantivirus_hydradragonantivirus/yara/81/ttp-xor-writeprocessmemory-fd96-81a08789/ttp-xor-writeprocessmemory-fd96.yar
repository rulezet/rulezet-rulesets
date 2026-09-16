rule TTP_XOR_WriteProcessMemory_fd96 {
  strings:
    $key_fd96 = { aa e4 [2] 98 c6 [2] 9e f3 [2] b0 f3 [2] 8f ef }

  condition:
    any of them
}