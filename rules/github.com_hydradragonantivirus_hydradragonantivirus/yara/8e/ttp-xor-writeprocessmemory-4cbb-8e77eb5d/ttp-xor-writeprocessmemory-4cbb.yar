rule TTP_XOR_WriteProcessMemory_4cbb {
  strings:
    $key_4cbb = { 1b c9 [2] 29 eb [2] 2f de [2] 01 de [2] 3e c2 }

  condition:
    any of them
}