rule TTP_XOR_WriteProcessMemory_fd49 {
  strings:
    $key_fd49 = { aa 3b [2] 98 19 [2] 9e 2c [2] b0 2c [2] 8f 30 }

  condition:
    any of them
}