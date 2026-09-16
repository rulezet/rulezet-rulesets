rule TTP_XOR_WriteProcessMemory_fdbc {
  strings:
    $key_fdbc = { aa ce [2] 98 ec [2] 9e d9 [2] b0 d9 [2] 8f c5 }

  condition:
    any of them
}