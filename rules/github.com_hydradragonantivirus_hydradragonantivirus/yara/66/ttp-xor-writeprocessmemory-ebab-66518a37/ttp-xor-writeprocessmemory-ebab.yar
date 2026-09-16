rule TTP_XOR_WriteProcessMemory_ebab {
  strings:
    $key_ebab = { bc d9 [2] 8e fb [2] 88 ce [2] a6 ce [2] 99 d2 }

  condition:
    any of them
}