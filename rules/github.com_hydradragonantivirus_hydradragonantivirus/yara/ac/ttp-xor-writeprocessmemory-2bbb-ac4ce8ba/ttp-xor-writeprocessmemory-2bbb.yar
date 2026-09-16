rule TTP_XOR_WriteProcessMemory_2bbb {
  strings:
    $key_2bbb = { 7c c9 [2] 4e eb [2] 48 de [2] 66 de [2] 59 c2 }

  condition:
    any of them
}