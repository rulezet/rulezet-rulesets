rule TTP_XOR_WriteProcessMemory_378c {
  strings:
    $key_378c = { 60 fe [2] 52 dc [2] 54 e9 [2] 7a e9 [2] 45 f5 }

  condition:
    any of them
}