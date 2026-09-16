rule TTP_XOR_WriteProcessMemory_1ccd {
  strings:
    $key_1ccd = { 4b bf [2] 79 9d [2] 7f a8 [2] 51 a8 [2] 6e b4 }

  condition:
    any of them
}