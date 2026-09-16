rule TTP_XOR_WriteProcessMemory_1f2d {
  strings:
    $key_1f2d = { 48 5f [2] 7a 7d [2] 7c 48 [2] 52 48 [2] 6d 54 }

  condition:
    any of them
}