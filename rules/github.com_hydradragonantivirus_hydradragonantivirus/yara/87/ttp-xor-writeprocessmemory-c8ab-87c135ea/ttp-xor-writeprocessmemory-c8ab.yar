rule TTP_XOR_WriteProcessMemory_c8ab {
  strings:
    $key_c8ab = { 9f d9 [2] ad fb [2] ab ce [2] 85 ce [2] ba d2 }

  condition:
    any of them
}