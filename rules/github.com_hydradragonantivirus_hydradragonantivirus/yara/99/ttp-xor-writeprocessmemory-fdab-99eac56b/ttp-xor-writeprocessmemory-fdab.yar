rule TTP_XOR_WriteProcessMemory_fdab {
  strings:
    $key_fdab = { aa d9 [2] 98 fb [2] 9e ce [2] b0 ce [2] 8f d2 }

  condition:
    any of them
}