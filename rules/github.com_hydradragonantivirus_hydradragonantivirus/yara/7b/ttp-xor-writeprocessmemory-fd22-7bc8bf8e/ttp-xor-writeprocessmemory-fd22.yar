rule TTP_XOR_WriteProcessMemory_fd22 {
  strings:
    $key_fd22 = { aa 50 [2] 98 72 [2] 9e 47 [2] b0 47 [2] 8f 5b }

  condition:
    any of them
}