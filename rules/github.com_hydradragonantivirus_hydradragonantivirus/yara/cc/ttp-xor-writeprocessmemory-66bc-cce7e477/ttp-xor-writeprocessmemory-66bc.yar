rule TTP_XOR_WriteProcessMemory_66bc {
  strings:
    $key_66bc = { 31 ce [2] 03 ec [2] 05 d9 [2] 2b d9 [2] 14 c5 }

  condition:
    any of them
}