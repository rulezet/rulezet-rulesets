rule TTP_XOR_WriteProcessMemory_fd6d {
  strings:
    $key_fd6d = { aa 1f [2] 98 3d [2] 9e 08 [2] b0 08 [2] 8f 14 }

  condition:
    any of them
}