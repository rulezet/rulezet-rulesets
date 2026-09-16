rule TTP_XOR_WriteProcessMemory_adab {
  strings:
    $key_adab = { fa d9 [2] c8 fb [2] ce ce [2] e0 ce [2] df d2 }

  condition:
    any of them
}