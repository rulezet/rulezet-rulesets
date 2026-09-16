rule TTP_XOR_WriteProcessMemory_fd30 {
  strings:
    $key_fd30 = { aa 42 [2] 98 60 [2] 9e 55 [2] b0 55 [2] 8f 49 }

  condition:
    any of them
}