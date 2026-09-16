rule TTP_XOR_WriteProcessMemory_390d {
  strings:
    $key_390d = { 6e 7f [2] 5c 5d [2] 5a 68 [2] 74 68 [2] 4b 74 }

  condition:
    any of them
}