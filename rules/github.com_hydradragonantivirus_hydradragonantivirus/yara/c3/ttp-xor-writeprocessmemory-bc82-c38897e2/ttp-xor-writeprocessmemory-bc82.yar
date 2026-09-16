rule TTP_XOR_WriteProcessMemory_bc82 {
  strings:
    $key_bc82 = { eb f0 [2] d9 d2 [2] df e7 [2] f1 e7 [2] ce fb }

  condition:
    any of them
}