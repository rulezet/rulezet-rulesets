rule TTP_XOR_WriteProcessMemory_fd0a {
  strings:
    $key_fd0a = { aa 78 [2] 98 5a [2] 9e 6f [2] b0 6f [2] 8f 73 }

  condition:
    any of them
}