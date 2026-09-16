rule TTP_XOR_WriteProcessMemory_fbbb {
  strings:
    $key_fbbb = { ac c9 [2] 9e eb [2] 98 de [2] b6 de [2] 89 c2 }

  condition:
    any of them
}