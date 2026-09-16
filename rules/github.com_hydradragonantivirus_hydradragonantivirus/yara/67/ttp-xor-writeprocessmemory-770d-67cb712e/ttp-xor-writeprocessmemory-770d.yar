rule TTP_XOR_WriteProcessMemory_770d {
  strings:
    $key_770d = { 20 7f [2] 12 5d [2] 14 68 [2] 3a 68 [2] 05 74 }

  condition:
    any of them
}