rule TTP_XOR_WriteProcessMemory_0b5d {
  strings:
    $key_0b5d = { 5c 2f [2] 6e 0d [2] 68 38 [2] 46 38 [2] 79 24 }

  condition:
    any of them
}