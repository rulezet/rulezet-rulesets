rule TTP_XOR_WriteProcessMemory_fb9e {
  strings:
    $key_fb9e = { ac ec [2] 9e ce [2] 98 fb [2] b6 fb [2] 89 e7 }

  condition:
    any of them
}