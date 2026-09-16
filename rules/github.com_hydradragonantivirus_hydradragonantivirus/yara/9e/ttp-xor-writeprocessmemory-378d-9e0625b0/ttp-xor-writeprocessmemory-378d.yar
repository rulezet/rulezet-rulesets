rule TTP_XOR_WriteProcessMemory_378d {
  strings:
    $key_378d = { 60 ff [2] 52 dd [2] 54 e8 [2] 7a e8 [2] 45 f4 }

  condition:
    any of them
}