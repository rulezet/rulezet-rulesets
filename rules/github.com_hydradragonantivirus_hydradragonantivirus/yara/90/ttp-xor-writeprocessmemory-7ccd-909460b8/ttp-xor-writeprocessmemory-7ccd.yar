rule TTP_XOR_WriteProcessMemory_7ccd {
  strings:
    $key_7ccd = { 2b bf [2] 19 9d [2] 1f a8 [2] 31 a8 [2] 0e b4 }

  condition:
    any of them
}