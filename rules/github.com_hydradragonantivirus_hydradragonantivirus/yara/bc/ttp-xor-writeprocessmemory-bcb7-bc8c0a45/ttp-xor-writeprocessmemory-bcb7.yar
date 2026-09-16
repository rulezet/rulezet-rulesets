rule TTP_XOR_WriteProcessMemory_bcb7 {
  strings:
    $key_bcb7 = { eb c5 [2] d9 e7 [2] df d2 [2] f1 d2 [2] ce ce }

  condition:
    any of them
}