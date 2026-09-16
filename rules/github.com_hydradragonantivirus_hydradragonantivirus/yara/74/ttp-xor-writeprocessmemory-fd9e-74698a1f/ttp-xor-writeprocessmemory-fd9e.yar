rule TTP_XOR_WriteProcessMemory_fd9e {
  strings:
    $key_fd9e = { aa ec [2] 98 ce [2] 9e fb [2] b0 fb [2] 8f e7 }

  condition:
    any of them
}