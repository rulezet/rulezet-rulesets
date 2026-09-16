rule TTP_XOR_WriteProcessMemory_dcbc {
  strings:
    $key_dcbc = { 8b ce [2] b9 ec [2] bf d9 [2] 91 d9 [2] ae c5 }

  condition:
    any of them
}