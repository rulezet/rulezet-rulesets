rule TTP_XOR_WriteProcessMemory_1bbb {
  strings:
    $key_1bbb = { 4c c9 [2] 7e eb [2] 78 de [2] 56 de [2] 69 c2 }

  condition:
    any of them
}