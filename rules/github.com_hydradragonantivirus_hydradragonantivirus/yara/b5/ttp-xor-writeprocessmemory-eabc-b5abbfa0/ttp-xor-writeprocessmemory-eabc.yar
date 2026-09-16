rule TTP_XOR_WriteProcessMemory_eabc {
  strings:
    $key_eabc = { bd ce [2] 8f ec [2] 89 d9 [2] a7 d9 [2] 98 c5 }

  condition:
    any of them
}