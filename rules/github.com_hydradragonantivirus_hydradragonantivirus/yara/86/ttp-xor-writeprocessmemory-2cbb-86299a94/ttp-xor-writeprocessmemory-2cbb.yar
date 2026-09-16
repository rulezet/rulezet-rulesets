rule TTP_XOR_WriteProcessMemory_2cbb {
  strings:
    $key_2cbb = { 7b c9 [2] 49 eb [2] 4f de [2] 61 de [2] 5e c2 }

  condition:
    any of them
}