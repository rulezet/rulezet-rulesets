rule TTP_XOR_WriteProcessMemory_742d {
  strings:
    $key_742d = { 23 5f [2] 11 7d [2] 17 48 [2] 39 48 [2] 06 54 }

  condition:
    any of them
}