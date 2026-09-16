rule TTP_XOR_WriteProcessMemory_911b {
  strings:
    $key_911b = { c6 69 [2] f4 4b [2] f2 7e [2] dc 7e [2] e3 62 }

  condition:
    any of them
}