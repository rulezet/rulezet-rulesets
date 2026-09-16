rule TTP_XOR_WriteProcessMemory_fd24 {
  strings:
    $key_fd24 = { aa 56 [2] 98 74 [2] 9e 41 [2] b0 41 [2] 8f 5d }

  condition:
    any of them
}