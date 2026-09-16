rule TTP_XOR_WriteProcessMemory_419c {
  strings:
    $key_419c = { 16 ee [2] 24 cc [2] 22 f9 [2] 0c f9 [2] 33 e5 }

  condition:
    any of them
}