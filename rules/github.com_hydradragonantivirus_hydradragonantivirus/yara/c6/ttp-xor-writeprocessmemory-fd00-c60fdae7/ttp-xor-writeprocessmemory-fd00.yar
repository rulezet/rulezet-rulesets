rule TTP_XOR_WriteProcessMemory_fd00 {
  strings:
    $key_fd00 = { aa 72 [2] 98 50 [2] 9e 65 [2] b0 65 [2] 8f 79 }

  condition:
    any of them
}