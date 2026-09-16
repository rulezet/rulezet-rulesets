rule TTP_XOR_WriteProcessMemory_fd3c {
  strings:
    $key_fd3c = { aa 4e [2] 98 6c [2] 9e 59 [2] b0 59 [2] 8f 45 }

  condition:
    any of them
}