rule TTP_XOR_WriteProcessMemory_265d {
  strings:
    $key_265d = { 71 2f [2] 43 0d [2] 45 38 [2] 6b 38 [2] 54 24 }

  condition:
    any of them
}