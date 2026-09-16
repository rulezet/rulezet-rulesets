rule TTP_XOR_WriteProcessMemory_fd7d {
  strings:
    $key_fd7d = { aa 0f [2] 98 2d [2] 9e 18 [2] b0 18 [2] 8f 04 }

  condition:
    any of them
}