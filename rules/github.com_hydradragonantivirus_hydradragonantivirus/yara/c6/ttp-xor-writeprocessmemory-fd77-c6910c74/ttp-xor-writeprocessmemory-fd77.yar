rule TTP_XOR_WriteProcessMemory_fd77 {
  strings:
    $key_fd77 = { aa 05 [2] 98 27 [2] 9e 12 [2] b0 12 [2] 8f 0e }

  condition:
    any of them
}