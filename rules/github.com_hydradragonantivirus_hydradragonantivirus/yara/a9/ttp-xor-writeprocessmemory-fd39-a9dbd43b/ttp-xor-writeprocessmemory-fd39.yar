rule TTP_XOR_WriteProcessMemory_fd39 {
  strings:
    $key_fd39 = { aa 4b [2] 98 69 [2] 9e 5c [2] b0 5c [2] 8f 40 }

  condition:
    any of them
}