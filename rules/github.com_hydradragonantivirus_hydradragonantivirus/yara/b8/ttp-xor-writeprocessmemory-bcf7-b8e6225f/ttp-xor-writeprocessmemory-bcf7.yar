rule TTP_XOR_WriteProcessMemory_bcf7 {
  strings:
    $key_bcf7 = { eb 85 [2] d9 a7 [2] df 92 [2] f1 92 [2] ce 8e }

  condition:
    any of them
}