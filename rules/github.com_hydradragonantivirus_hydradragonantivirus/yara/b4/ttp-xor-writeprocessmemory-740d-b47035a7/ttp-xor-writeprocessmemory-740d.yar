rule TTP_XOR_WriteProcessMemory_740d {
  strings:
    $key_740d = { 23 7f [2] 11 5d [2] 17 68 [2] 39 68 [2] 06 74 }

  condition:
    any of them
}