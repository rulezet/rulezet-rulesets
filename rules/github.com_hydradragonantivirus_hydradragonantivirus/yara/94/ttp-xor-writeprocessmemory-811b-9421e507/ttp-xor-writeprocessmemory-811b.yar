rule TTP_XOR_WriteProcessMemory_811b {
  strings:
    $key_811b = { d6 69 [2] e4 4b [2] e2 7e [2] cc 7e [2] f3 62 }

  condition:
    any of them
}