rule TTP_XOR_WriteProcessMemory_3cbb {
  strings:
    $key_3cbb = { 6b c9 [2] 59 eb [2] 5f de [2] 71 de [2] 4e c2 }

  condition:
    any of them
}