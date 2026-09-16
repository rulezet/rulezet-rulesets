rule TTP_XOR_WriteProcessMemory_5bbb {
  strings:
    $key_5bbb = { 0c c9 [2] 3e eb [2] 38 de [2] 16 de [2] 29 c2 }

  condition:
    any of them
}