rule TTP_XOR_WriteProcessMemory_7d1d {
  strings:
    $key_7d1d = { 2a 6f [2] 18 4d [2] 1e 78 [2] 30 78 [2] 0f 64 }

  condition:
    any of them
}