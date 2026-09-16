rule TTP_XOR_WriteProcessMemory_441d {
  strings:
    $key_441d = { 13 6f [2] 21 4d [2] 27 78 [2] 09 78 [2] 36 64 }

  condition:
    any of them
}