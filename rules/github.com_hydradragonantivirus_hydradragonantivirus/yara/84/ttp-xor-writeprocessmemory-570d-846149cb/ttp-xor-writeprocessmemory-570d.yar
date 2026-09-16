rule TTP_XOR_WriteProcessMemory_570d {
  strings:
    $key_570d = { 00 7f [2] 32 5d [2] 34 68 [2] 1a 68 [2] 25 74 }

  condition:
    any of them
}