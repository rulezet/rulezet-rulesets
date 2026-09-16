rule TTP_XOR_WriteProcessMemory_48ab {
  strings:
    $key_48ab = { 1f d9 [2] 2d fb [2] 2b ce [2] 05 ce [2] 3a d2 }

  condition:
    any of them
}