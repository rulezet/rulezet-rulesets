rule TTP_XOR_WriteProcessMemory_822b {
  strings:
    $key_822b = { d5 59 [2] e7 7b [2] e1 4e [2] cf 4e [2] f0 52 }

  condition:
    any of them
}