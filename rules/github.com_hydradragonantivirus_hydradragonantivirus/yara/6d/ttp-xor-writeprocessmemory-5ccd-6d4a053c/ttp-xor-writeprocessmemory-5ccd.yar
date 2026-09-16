rule TTP_XOR_WriteProcessMemory_5ccd {
  strings:
    $key_5ccd = { 0b bf [2] 39 9d [2] 3f a8 [2] 11 a8 [2] 2e b4 }

  condition:
    any of them
}