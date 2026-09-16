rule TTP_XOR_WriteProcessMemory_fd01 {
  strings:
    $key_fd01 = { aa 73 [2] 98 51 [2] 9e 64 [2] b0 64 [2] 8f 78 }

  condition:
    any of them
}