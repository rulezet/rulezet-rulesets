rule TTP_XOR_WriteProcessMemory_bcb1 {
  strings:
    $key_bcb1 = { eb c3 [2] d9 e1 [2] df d4 [2] f1 d4 [2] ce c8 }

  condition:
    any of them
}