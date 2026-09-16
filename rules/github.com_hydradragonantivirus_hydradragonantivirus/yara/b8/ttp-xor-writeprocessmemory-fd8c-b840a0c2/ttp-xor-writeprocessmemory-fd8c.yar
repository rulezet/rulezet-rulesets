rule TTP_XOR_WriteProcessMemory_fd8c {
  strings:
    $key_fd8c = { aa fe [2] 98 dc [2] 9e e9 [2] b0 e9 [2] 8f f5 }

  condition:
    any of them
}