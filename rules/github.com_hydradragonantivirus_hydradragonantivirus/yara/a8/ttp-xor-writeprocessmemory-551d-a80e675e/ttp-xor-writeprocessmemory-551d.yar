rule TTP_XOR_WriteProcessMemory_551d {
  strings:
    $key_551d = { 02 6f [2] 30 4d [2] 36 78 [2] 18 78 [2] 27 64 }

  condition:
    any of them
}