rule TTP_XOR_WriteProcessMemory_fd36 {
  strings:
    $key_fd36 = { aa 44 [2] 98 66 [2] 9e 53 [2] b0 53 [2] 8f 4f }

  condition:
    any of them
}