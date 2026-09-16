rule TTP_XOR_WriteProcessMemory_710d {
  strings:
    $key_710d = { 26 7f [2] 14 5d [2] 12 68 [2] 3c 68 [2] 03 74 }

  condition:
    any of them
}