rule TTP_XOR_WriteProcessMemory_fd1a {
  strings:
    $key_fd1a = { aa 68 [2] 98 4a [2] 9e 7f [2] b0 7f [2] 8f 63 }

  condition:
    any of them
}