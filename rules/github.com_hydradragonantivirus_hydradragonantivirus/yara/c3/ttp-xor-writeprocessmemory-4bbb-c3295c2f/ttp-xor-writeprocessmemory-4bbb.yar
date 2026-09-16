rule TTP_XOR_WriteProcessMemory_4bbb {
  strings:
    $key_4bbb = { 1c c9 [2] 2e eb [2] 28 de [2] 06 de [2] 39 c2 }

  condition:
    any of them
}