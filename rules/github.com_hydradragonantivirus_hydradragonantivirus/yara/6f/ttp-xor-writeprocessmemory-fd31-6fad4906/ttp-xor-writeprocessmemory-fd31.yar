rule TTP_XOR_WriteProcessMemory_fd31 {
  strings:
    $key_fd31 = { aa 43 [2] 98 61 [2] 9e 54 [2] b0 54 [2] 8f 48 }

  condition:
    any of them
}