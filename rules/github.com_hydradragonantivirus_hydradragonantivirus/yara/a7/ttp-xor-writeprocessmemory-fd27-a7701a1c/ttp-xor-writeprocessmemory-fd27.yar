rule TTP_XOR_WriteProcessMemory_fd27 {
  strings:
    $key_fd27 = { aa 55 [2] 98 77 [2] 9e 42 [2] b0 42 [2] 8f 5e }

  condition:
    any of them
}