rule TTP_XOR_WriteProcessMemory_799e {
  strings:
    $key_799e = { 2e ec [2] 1c ce [2] 1a fb [2] 34 fb [2] 0b e7 }

  condition:
    any of them
}