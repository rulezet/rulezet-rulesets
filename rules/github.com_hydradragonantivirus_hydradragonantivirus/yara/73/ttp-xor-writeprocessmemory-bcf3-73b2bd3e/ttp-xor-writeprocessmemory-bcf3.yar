rule TTP_XOR_WriteProcessMemory_bcf3 {
  strings:
    $key_bcf3 = { eb 81 [2] d9 a3 [2] df 96 [2] f1 96 [2] ce 8a }

  condition:
    any of them
}