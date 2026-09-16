rule TTP_XOR_WriteProcessMemory_928c {
  strings:
    $key_928c = { c5 fe [2] f7 dc [2] f1 e9 [2] df e9 [2] e0 f5 }

  condition:
    any of them
}