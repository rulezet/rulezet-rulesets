rule TTP_XOR_WriteProcessMemory_853e {
  strings:
    $key_853e = { d2 4c [2] e0 6e [2] e6 5b [2] c8 5b [2] f7 47 }

  condition:
    any of them
}