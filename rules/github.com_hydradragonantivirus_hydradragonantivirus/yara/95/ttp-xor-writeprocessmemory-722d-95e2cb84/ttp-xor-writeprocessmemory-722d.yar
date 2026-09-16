rule TTP_XOR_WriteProcessMemory_722d {
  strings:
    $key_722d = { 25 5f [2] 17 7d [2] 11 48 [2] 3f 48 [2] 00 54 }

  condition:
    any of them
}