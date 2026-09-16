rule TTP_XOR_WriteProcessMemory_ffab {
  strings:
    $key_ffab = { a8 d9 [2] 9a fb [2] 9c ce [2] b2 ce [2] 8d d2 }

  condition:
    any of them
}