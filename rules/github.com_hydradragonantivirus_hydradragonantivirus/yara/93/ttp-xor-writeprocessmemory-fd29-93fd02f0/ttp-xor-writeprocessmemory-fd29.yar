rule TTP_XOR_WriteProcessMemory_fd29 {
  strings:
    $key_fd29 = { aa 5b [2] 98 79 [2] 9e 4c [2] b0 4c [2] 8f 50 }

  condition:
    any of them
}