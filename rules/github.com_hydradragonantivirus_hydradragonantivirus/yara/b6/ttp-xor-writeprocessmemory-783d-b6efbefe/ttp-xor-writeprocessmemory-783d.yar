rule TTP_XOR_WriteProcessMemory_783d {
  strings:
    $key_783d = { 2f 4f [2] 1d 6d [2] 1b 58 [2] 35 58 [2] 0a 44 }

  condition:
    any of them
}