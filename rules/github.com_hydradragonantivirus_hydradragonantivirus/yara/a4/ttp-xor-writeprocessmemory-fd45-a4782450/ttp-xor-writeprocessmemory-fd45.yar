rule TTP_XOR_WriteProcessMemory_fd45 {
  strings:
    $key_fd45 = { aa 37 [2] 98 15 [2] 9e 20 [2] b0 20 [2] 8f 3c }

  condition:
    any of them
}