rule TTP_XOR_WriteProcessMemory_5cbb {
  strings:
    $key_5cbb = { 0b c9 [2] 39 eb [2] 3f de [2] 11 de [2] 2e c2 }

  condition:
    any of them
}