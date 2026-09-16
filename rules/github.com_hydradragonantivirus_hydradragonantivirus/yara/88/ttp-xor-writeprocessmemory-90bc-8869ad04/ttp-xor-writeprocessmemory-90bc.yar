rule TTP_XOR_WriteProcessMemory_90bc {
  strings:
    $key_90bc = { c7 ce [2] f5 ec [2] f3 d9 [2] dd d9 [2] e2 c5 }

  condition:
    any of them
}