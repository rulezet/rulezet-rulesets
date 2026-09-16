rule TTP_XOR_WriteProcessMemory_422d {
  strings:
    $key_422d = { 15 5f [2] 27 7d [2] 21 48 [2] 0f 48 [2] 30 54 }

  condition:
    any of them
}