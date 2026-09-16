rule TTP_XOR_WriteProcessMemory_fd3d {
  strings:
    $key_fd3d = { aa 4f [2] 98 6d [2] 9e 58 [2] b0 58 [2] 8f 44 }

  condition:
    any of them
}