rule TTP_XOR_WriteProcessMemory_b1ab {
  strings:
    $key_b1ab = { e6 d9 [2] d4 fb [2] d2 ce [2] fc ce [2] c3 d2 }

  condition:
    any of them
}