rule TTP_XOR_WriteProcessMemory_7d2d {
  strings:
    $key_7d2d = { 2a 5f [2] 18 7d [2] 1e 48 [2] 30 48 [2] 0f 54 }

  condition:
    any of them
}