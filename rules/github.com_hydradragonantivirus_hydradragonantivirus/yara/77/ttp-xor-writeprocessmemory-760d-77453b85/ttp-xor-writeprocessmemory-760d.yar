rule TTP_XOR_WriteProcessMemory_760d {
  strings:
    $key_760d = { 21 7f [2] 13 5d [2] 15 68 [2] 3b 68 [2] 04 74 }

  condition:
    any of them
}