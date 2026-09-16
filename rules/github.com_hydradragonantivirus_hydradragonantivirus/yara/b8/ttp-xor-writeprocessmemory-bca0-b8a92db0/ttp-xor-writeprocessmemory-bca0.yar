rule TTP_XOR_WriteProcessMemory_bca0 {
  strings:
    $key_bca0 = { eb d2 [2] d9 f0 [2] df c5 [2] f1 c5 [2] ce d9 }

  condition:
    any of them
}