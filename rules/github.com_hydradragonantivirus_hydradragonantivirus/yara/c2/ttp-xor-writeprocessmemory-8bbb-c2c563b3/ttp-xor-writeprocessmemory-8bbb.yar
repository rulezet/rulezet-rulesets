rule TTP_XOR_WriteProcessMemory_8bbb {
  strings:
    $key_8bbb = { dc c9 [2] ee eb [2] e8 de [2] c6 de [2] f9 c2 }

  condition:
    any of them
}