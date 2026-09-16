rule TTP_XOR_WriteProcessMemory_34bc {
  strings:
    $key_34bc = { 63 ce [2] 51 ec [2] 57 d9 [2] 79 d9 [2] 46 c5 }

  condition:
    any of them
}