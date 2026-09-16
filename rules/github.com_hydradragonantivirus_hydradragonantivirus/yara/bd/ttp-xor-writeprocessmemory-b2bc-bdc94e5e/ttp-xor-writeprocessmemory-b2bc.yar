rule TTP_XOR_WriteProcessMemory_b2bc {
  strings:
    $key_b2bc = { e5 ce [2] d7 ec [2] d1 d9 [2] ff d9 [2] c0 c5 }

  condition:
    any of them
}