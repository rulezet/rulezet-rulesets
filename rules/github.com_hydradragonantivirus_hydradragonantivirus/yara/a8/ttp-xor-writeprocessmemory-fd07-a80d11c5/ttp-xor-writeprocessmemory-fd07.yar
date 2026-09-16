rule TTP_XOR_WriteProcessMemory_fd07 {
  strings:
    $key_fd07 = { aa 75 [2] 98 57 [2] 9e 62 [2] b0 62 [2] 8f 7e }

  condition:
    any of them
}