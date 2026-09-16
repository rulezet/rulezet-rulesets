rule TTP_XOR_WriteProcessMemory_fd58 {
  strings:
    $key_fd58 = { aa 2a [2] 98 08 [2] 9e 3d [2] b0 3d [2] 8f 21 }

  condition:
    any of them
}