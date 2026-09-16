rule TTP_XOR_WriteProcessMemory_fd59 {
  strings:
    $key_fd59 = { aa 2b [2] 98 09 [2] 9e 3c [2] b0 3c [2] 8f 20 }

  condition:
    any of them
}