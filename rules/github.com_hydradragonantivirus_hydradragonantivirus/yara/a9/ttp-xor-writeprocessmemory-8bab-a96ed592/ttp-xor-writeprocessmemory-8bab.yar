rule TTP_XOR_WriteProcessMemory_8bab {
  strings:
    $key_8bab = { dc d9 [2] ee fb [2] e8 ce [2] c6 ce [2] f9 d2 }

  condition:
    any of them
}