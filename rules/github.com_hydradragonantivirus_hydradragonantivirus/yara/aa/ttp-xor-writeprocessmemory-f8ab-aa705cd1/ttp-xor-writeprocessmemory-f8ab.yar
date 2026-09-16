rule TTP_XOR_WriteProcessMemory_f8ab {
  strings:
    $key_f8ab = { af d9 [2] 9d fb [2] 9b ce [2] b5 ce [2] 8a d2 }

  condition:
    any of them
}