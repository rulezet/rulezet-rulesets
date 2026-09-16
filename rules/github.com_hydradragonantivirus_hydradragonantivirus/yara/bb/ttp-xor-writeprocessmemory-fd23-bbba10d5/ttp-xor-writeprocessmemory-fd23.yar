rule TTP_XOR_WriteProcessMemory_fd23 {
  strings:
    $key_fd23 = { aa 51 [2] 98 73 [2] 9e 46 [2] b0 46 [2] 8f 5a }

  condition:
    any of them
}