rule TTP_XOR_WriteProcessMemory_401d {
  strings:
    $key_401d = { 17 6f [2] 25 4d [2] 23 78 [2] 0d 78 [2] 32 64 }

  condition:
    any of them
}