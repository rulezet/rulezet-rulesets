rule TTP_XOR_WriteProcessMemory_25ab {
  strings:
    $key_25ab = { 72 d9 [2] 40 fb [2] 46 ce [2] 68 ce [2] 57 d2 }

  condition:
    any of them
}