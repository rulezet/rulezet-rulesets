rule TTP_XOR_WriteProcessMemory_cfbc {
  strings:
    $key_cfbc = { 98 ce [2] aa ec [2] ac d9 [2] 82 d9 [2] bd c5 }

  condition:
    any of them
}