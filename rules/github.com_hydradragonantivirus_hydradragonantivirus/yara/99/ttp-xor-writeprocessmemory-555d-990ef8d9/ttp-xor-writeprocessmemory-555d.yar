rule TTP_XOR_WriteProcessMemory_555d {
  strings:
    $key_555d = { 02 2f [2] 30 0d [2] 36 38 [2] 18 38 [2] 27 24 }

  condition:
    any of them
}