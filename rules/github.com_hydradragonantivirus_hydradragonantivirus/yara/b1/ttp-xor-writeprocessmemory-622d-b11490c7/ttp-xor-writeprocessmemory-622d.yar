rule TTP_XOR_WriteProcessMemory_622d {
  strings:
    $key_622d = { 35 5f [2] 07 7d [2] 01 48 [2] 2f 48 [2] 10 54 }

  condition:
    any of them
}