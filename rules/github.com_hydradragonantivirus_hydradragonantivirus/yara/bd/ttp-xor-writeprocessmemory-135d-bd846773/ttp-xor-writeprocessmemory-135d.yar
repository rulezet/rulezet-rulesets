rule TTP_XOR_WriteProcessMemory_135d {
  strings:
    $key_135d = { 44 2f [2] 76 0d [2] 70 38 [2] 5e 38 [2] 61 24 }

  condition:
    any of them
}