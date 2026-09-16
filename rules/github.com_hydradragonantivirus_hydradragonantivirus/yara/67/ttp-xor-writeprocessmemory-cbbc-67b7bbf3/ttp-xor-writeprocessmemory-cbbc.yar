rule TTP_XOR_WriteProcessMemory_cbbc {
  strings:
    $key_cbbc = { 9c ce [2] ae ec [2] a8 d9 [2] 86 d9 [2] b9 c5 }

  condition:
    any of them
}