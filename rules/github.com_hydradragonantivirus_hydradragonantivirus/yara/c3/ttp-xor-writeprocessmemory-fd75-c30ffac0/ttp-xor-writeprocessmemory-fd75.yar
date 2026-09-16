rule TTP_XOR_WriteProcessMemory_fd75 {
  strings:
    $key_fd75 = { aa 07 [2] 98 25 [2] 9e 10 [2] b0 10 [2] 8f 0c }

  condition:
    any of them
}