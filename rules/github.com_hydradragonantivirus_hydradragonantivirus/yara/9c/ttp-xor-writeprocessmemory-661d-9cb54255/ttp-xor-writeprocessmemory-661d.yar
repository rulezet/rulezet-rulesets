rule TTP_XOR_WriteProcessMemory_661d {
  strings:
    $key_661d = { 31 6f [2] 03 4d [2] 05 78 [2] 2b 78 [2] 14 64 }

  condition:
    any of them
}