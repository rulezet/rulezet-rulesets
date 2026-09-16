rule TTP_XOR_WriteProcessMemory_36ab {
  strings:
    $key_36ab = { 61 d9 [2] 53 fb [2] 55 ce [2] 7b ce [2] 44 d2 }

  condition:
    any of them
}