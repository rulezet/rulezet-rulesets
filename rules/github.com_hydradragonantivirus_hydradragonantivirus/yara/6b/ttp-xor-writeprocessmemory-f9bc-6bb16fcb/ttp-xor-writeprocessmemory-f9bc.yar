rule TTP_XOR_WriteProcessMemory_f9bc {
  strings:
    $key_f9bc = { ae ce [2] 9c ec [2] 9a d9 [2] b4 d9 [2] 8b c5 }

  condition:
    any of them
}