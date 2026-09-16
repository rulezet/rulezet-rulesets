rule TTP_XOR_WriteProcessMemory_7d5d {
  strings:
    $key_7d5d = { 2a 2f [2] 18 0d [2] 1e 38 [2] 30 38 [2] 0f 24 }

  condition:
    any of them
}