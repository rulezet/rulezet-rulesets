rule TTP_XOR_WriteProcessMemory_edab {
  strings:
    $key_edab = { ba d9 [2] 88 fb [2] 8e ce [2] a0 ce [2] 9f d2 }

  condition:
    any of them
}