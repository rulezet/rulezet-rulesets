rule TTP_XOR_WriteProcessMemory_fd10 {
  strings:
    $key_fd10 = { aa 62 [2] 98 40 [2] 9e 75 [2] b0 75 [2] 8f 69 }

  condition:
    any of them
}