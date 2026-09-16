rule TTP_XOR_WriteProcessMemory_723d {
  strings:
    $key_723d = { 25 4f [2] 17 6d [2] 11 58 [2] 3f 58 [2] 00 44 }

  condition:
    any of them
}