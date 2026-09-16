rule TTP_XOR_WriteProcessMemory_e1bc {
  strings:
    $key_e1bc = { b6 ce [2] 84 ec [2] 82 d9 [2] ac d9 [2] 93 c5 }

  condition:
    any of them
}