rule TTP_XOR_WriteProcessMemory_fd97 {
  strings:
    $key_fd97 = { aa e5 [2] 98 c7 [2] 9e f2 [2] b0 f2 [2] 8f ee }

  condition:
    any of them
}