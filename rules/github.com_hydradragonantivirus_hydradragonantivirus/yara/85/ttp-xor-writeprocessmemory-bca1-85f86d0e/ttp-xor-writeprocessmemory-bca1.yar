rule TTP_XOR_WriteProcessMemory_bca1 {
  strings:
    $key_bca1 = { eb d3 [2] d9 f1 [2] df c4 [2] f1 c4 [2] ce d8 }

  condition:
    any of them
}