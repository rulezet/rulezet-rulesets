rule TTP_XOR_WriteProcessMemory_751d {
  strings:
    $key_751d = { 22 6f [2] 10 4d [2] 16 78 [2] 38 78 [2] 07 64 }

  condition:
    any of them
}