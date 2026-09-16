rule TTP_XOR_WriteProcessMemory_06ab {
  strings:
    $key_06ab = { 51 d9 [2] 63 fb [2] 65 ce [2] 4b ce [2] 74 d2 }

  condition:
    any of them
}