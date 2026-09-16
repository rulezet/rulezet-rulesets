rule TTP_XOR_WriteProcessMemory_3b2d {
  strings:
    $key_3b2d = { 6c 5f [2] 5e 7d [2] 58 48 [2] 76 48 [2] 49 54 }

  condition:
    any of them
}