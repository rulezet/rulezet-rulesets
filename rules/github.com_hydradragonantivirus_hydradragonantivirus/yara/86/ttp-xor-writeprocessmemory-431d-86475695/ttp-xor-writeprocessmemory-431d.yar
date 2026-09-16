rule TTP_XOR_WriteProcessMemory_431d {
  strings:
    $key_431d = { 14 6f [2] 26 4d [2] 20 78 [2] 0e 78 [2] 31 64 }

  condition:
    any of them
}