rule TTP_XOR_WriteProcessMemory_fd9c {
  strings:
    $key_fd9c = { aa ee [2] 98 cc [2] 9e f9 [2] b0 f9 [2] 8f e5 }

  condition:
    any of them
}