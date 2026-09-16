rule TTP_XOR_WriteProcessMemory_94bc {
  strings:
    $key_94bc = { c3 ce [2] f1 ec [2] f7 d9 [2] d9 d9 [2] e6 c5 }

  condition:
    any of them
}