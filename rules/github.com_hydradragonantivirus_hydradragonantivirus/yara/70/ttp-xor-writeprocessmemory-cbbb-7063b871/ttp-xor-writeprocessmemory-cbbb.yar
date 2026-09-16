rule TTP_XOR_WriteProcessMemory_cbbb {
  strings:
    $key_cbbb = { 9c c9 [2] ae eb [2] a8 de [2] 86 de [2] b9 c2 }

  condition:
    any of them
}