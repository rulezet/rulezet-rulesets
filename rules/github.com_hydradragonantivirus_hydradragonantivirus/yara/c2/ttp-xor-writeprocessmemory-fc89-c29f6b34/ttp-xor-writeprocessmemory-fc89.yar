rule TTP_XOR_WriteProcessMemory_fc89 {
  strings:
    $key_fc89 = { ab fb [2] 99 d9 [2] 9f ec [2] b1 ec [2] 8e f0 }

  condition:
    any of them
}