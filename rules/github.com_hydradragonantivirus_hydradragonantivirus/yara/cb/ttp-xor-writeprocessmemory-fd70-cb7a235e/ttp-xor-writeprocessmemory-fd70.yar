rule TTP_XOR_WriteProcessMemory_fd70 {
  strings:
    $key_fd70 = { aa 02 [2] 98 20 [2] 9e 15 [2] b0 15 [2] 8f 09 }

  condition:
    any of them
}