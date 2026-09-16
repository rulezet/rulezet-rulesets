rule TTP_XOR_WriteProcessMemory_7d4d {
  strings:
    $key_7d4d = { 2a 3f [2] 18 1d [2] 1e 28 [2] 30 28 [2] 0f 34 }

  condition:
    any of them
}