rule TTP_XOR_WriteProcessMemory_fd99 {
  strings:
    $key_fd99 = { aa eb [2] 98 c9 [2] 9e fc [2] b0 fc [2] 8f e0 }

  condition:
    any of them
}