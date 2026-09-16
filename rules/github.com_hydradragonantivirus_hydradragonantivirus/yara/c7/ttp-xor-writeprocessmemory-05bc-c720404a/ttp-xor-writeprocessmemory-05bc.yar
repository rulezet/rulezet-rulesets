rule TTP_XOR_WriteProcessMemory_05bc {
  strings:
    $key_05bc = { 52 ce [2] 60 ec [2] 66 d9 [2] 48 d9 [2] 77 c5 }

  condition:
    any of them
}