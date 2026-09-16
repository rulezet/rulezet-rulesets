rule TTP_XOR_WriteProcessMemory_cf9e {
  strings:
    $key_cf9e = { 98 ec [2] aa ce [2] ac fb [2] 82 fb [2] bd e7 }

  condition:
    any of them
}