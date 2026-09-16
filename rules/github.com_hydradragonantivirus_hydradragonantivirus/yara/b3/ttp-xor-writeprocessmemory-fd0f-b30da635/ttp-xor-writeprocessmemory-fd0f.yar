rule TTP_XOR_WriteProcessMemory_fd0f {
  strings:
    $key_fd0f = { aa 7d [2] 98 5f [2] 9e 6a [2] b0 6a [2] 8f 76 }

  condition:
    any of them
}