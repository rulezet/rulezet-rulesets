rule TTP_XOR_WriteProcessMemory_bcb2 {
  strings:
    $key_bcb2 = { eb c0 [2] d9 e2 [2] df d7 [2] f1 d7 [2] ce cb }

  condition:
    any of them
}