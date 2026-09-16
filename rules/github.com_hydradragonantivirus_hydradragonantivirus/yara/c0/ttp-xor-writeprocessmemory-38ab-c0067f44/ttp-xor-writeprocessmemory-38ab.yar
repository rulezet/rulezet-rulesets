rule TTP_XOR_WriteProcessMemory_38ab {
  strings:
    $key_38ab = { 6f d9 [2] 5d fb [2] 5b ce [2] 75 ce [2] 4a d2 }

  condition:
    any of them
}