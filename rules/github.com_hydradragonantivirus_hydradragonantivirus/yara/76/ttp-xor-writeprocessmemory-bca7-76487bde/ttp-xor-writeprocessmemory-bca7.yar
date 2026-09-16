rule TTP_XOR_WriteProcessMemory_bca7 {
  strings:
    $key_bca7 = { eb d5 [2] d9 f7 [2] df c2 [2] f1 c2 [2] ce de }

  condition:
    any of them
}