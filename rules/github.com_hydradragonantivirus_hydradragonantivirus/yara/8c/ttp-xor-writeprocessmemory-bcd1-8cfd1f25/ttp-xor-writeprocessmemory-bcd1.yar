rule TTP_XOR_WriteProcessMemory_bcd1 {
  strings:
    $key_bcd1 = { eb a3 [2] d9 81 [2] df b4 [2] f1 b4 [2] ce a8 }

  condition:
    any of them
}