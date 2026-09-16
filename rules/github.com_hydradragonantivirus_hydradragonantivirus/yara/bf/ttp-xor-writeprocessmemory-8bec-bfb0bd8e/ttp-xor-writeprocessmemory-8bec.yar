rule TTP_XOR_WriteProcessMemory_8bec {
  strings:
    $key_8bec = { dc 9e [2] ee bc [2] e8 89 [2] c6 89 [2] f9 95 }

  condition:
    any of them
}