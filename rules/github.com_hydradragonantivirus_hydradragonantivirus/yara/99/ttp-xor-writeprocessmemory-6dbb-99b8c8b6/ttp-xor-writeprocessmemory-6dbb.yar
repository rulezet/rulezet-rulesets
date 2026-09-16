rule TTP_XOR_WriteProcessMemory_6dbb {
  strings:
    $key_6dbb = { 3a c9 [2] 08 eb [2] 0e de [2] 20 de [2] 1f c2 }

  condition:
    any of them
}