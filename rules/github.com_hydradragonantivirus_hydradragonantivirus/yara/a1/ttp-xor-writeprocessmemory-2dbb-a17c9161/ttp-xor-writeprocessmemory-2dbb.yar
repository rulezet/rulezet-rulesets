rule TTP_XOR_WriteProcessMemory_2dbb {
  strings:
    $key_2dbb = { 7a c9 [2] 48 eb [2] 4e de [2] 60 de [2] 5f c2 }

  condition:
    any of them
}