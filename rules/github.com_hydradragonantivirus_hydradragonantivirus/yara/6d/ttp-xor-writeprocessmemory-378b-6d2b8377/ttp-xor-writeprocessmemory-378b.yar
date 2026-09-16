rule TTP_XOR_WriteProcessMemory_378b {
  strings:
    $key_378b = { 60 f9 [2] 52 db [2] 54 ee [2] 7a ee [2] 45 f2 }

  condition:
    any of them
}