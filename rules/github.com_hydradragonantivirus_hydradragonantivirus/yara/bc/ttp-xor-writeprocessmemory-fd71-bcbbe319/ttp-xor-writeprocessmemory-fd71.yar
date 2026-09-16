rule TTP_XOR_WriteProcessMemory_fd71 {
  strings:
    $key_fd71 = { aa 03 [2] 98 21 [2] 9e 14 [2] b0 14 [2] 8f 08 }

  condition:
    any of them
}