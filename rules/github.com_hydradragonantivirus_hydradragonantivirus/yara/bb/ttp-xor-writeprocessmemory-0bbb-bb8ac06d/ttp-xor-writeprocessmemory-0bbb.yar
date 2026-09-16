rule TTP_XOR_WriteProcessMemory_0bbb {
  strings:
    $key_0bbb = { 5c c9 [2] 6e eb [2] 68 de [2] 46 de [2] 79 c2 }

  condition:
    any of them
}