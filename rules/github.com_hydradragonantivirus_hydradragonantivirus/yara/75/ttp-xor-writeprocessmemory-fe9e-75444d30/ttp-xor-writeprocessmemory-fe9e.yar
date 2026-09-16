rule TTP_XOR_WriteProcessMemory_fe9e {
  strings:
    $key_fe9e = { a9 ec [2] 9b ce [2] 9d fb [2] b3 fb [2] 8c e7 }

  condition:
    any of them
}