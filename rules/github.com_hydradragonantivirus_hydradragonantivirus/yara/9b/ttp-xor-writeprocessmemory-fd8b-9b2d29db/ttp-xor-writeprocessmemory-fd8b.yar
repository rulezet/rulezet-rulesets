rule TTP_XOR_WriteProcessMemory_fd8b {
  strings:
    $key_fd8b = { aa f9 [2] 98 db [2] 9e ee [2] b0 ee [2] 8f f2 }

  condition:
    any of them
}