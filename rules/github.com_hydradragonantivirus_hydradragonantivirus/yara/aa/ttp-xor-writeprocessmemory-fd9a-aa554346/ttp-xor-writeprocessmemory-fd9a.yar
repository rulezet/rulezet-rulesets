rule TTP_XOR_WriteProcessMemory_fd9a {
  strings:
    $key_fd9a = { aa e8 [2] 98 ca [2] 9e ff [2] b0 ff [2] 8f e3 }

  condition:
    any of them
}