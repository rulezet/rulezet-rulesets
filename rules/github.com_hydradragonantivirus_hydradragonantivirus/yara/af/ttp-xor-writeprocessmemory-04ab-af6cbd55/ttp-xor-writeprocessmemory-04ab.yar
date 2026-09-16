rule TTP_XOR_WriteProcessMemory_04ab {
  strings:
    $key_04ab = { 53 d9 [2] 61 fb [2] 67 ce [2] 49 ce [2] 76 d2 }

  condition:
    any of them
}