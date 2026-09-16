rule TTP_XOR_WriteProcessMemory_e522 {
  strings:
    $key_e522 = { b2 50 [2] 80 72 [2] 86 47 [2] a8 47 [2] 97 5b }

  condition:
    any of them
}