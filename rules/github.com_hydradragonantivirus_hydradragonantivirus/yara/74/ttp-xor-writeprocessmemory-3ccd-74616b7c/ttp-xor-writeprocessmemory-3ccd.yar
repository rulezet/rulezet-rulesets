rule TTP_XOR_WriteProcessMemory_3ccd {
  strings:
    $key_3ccd = { 6b bf [2] 59 9d [2] 5f a8 [2] 71 a8 [2] 4e b4 }

  condition:
    any of them
}