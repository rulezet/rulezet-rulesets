rule TTP_XOR_WriteProcessMemory_fd08 {
  strings:
    $key_fd08 = { aa 7a [2] 98 58 [2] 9e 6d [2] b0 6d [2] 8f 71 }

  condition:
    any of them
}