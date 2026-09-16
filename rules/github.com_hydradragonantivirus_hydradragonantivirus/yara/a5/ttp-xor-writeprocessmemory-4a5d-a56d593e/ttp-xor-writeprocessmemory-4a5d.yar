rule TTP_XOR_WriteProcessMemory_4a5d {
  strings:
    $key_4a5d = { 1d 2f [2] 2f 0d [2] 29 38 [2] 07 38 [2] 38 24 }

  condition:
    any of them
}