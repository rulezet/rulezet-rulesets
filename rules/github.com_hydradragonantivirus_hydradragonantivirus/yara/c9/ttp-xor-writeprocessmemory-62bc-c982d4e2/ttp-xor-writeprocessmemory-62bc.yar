rule TTP_XOR_WriteProcessMemory_62bc {
  strings:
    $key_62bc = { 35 ce [2] 07 ec [2] 01 d9 [2] 2f d9 [2] 10 c5 }

  condition:
    any of them
}