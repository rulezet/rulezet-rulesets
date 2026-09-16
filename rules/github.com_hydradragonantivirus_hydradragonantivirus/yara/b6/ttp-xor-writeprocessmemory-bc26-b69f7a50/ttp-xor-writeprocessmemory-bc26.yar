rule TTP_XOR_WriteProcessMemory_bc26 {
  strings:
    $key_bc26 = { eb 54 [2] d9 76 [2] df 43 [2] f1 43 [2] ce 5f }

  condition:
    any of them
}