rule TTP_XOR_WriteProcessMemory_e39e {
  strings:
    $key_e39e = { b4 ec [2] 86 ce [2] 80 fb [2] ae fb [2] 91 e7 }

  condition:
    any of them
}