rule TTP_XOR_WriteProcessMemory_76ab {
  strings:
    $key_76ab = { 21 d9 [2] 13 fb [2] 15 ce [2] 3b ce [2] 04 d2 }

  condition:
    any of them
}