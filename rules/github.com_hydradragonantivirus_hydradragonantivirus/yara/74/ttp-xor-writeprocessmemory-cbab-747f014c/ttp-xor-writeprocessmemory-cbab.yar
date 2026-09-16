rule TTP_XOR_WriteProcessMemory_cbab {
  strings:
    $key_cbab = { 9c d9 [2] ae fb [2] a8 ce [2] 86 ce [2] b9 d2 }

  condition:
    any of them
}