rule TTP_XOR_WriteProcessMemory_fd41 {
  strings:
    $key_fd41 = { aa 33 [2] 98 11 [2] 9e 24 [2] b0 24 [2] 8f 38 }

  condition:
    any of them
}