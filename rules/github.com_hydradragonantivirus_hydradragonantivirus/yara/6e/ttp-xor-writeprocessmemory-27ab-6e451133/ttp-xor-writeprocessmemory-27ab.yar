rule TTP_XOR_WriteProcessMemory_27ab {
  strings:
    $key_27ab = { 70 d9 [2] 42 fb [2] 44 ce [2] 6a ce [2] 55 d2 }

  condition:
    any of them
}