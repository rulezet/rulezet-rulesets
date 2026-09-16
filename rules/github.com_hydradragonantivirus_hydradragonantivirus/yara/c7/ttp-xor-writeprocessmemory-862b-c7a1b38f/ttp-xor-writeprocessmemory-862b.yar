rule TTP_XOR_WriteProcessMemory_862b {
  strings:
    $key_862b = { d1 59 [2] e3 7b [2] e5 4e [2] cb 4e [2] f4 52 }

  condition:
    any of them
}