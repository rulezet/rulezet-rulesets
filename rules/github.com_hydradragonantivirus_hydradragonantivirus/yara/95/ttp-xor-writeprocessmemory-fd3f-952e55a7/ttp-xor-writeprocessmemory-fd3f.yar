rule TTP_XOR_WriteProcessMemory_fd3f {
  strings:
    $key_fd3f = { aa 4d [2] 98 6f [2] 9e 5a [2] b0 5a [2] 8f 46 }

  condition:
    any of them
}