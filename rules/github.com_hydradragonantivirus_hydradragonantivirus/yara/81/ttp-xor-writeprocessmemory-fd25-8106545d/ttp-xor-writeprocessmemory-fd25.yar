rule TTP_XOR_WriteProcessMemory_fd25 {
  strings:
    $key_fd25 = { aa 57 [2] 98 75 [2] 9e 40 [2] b0 40 [2] 8f 5c }

  condition:
    any of them
}