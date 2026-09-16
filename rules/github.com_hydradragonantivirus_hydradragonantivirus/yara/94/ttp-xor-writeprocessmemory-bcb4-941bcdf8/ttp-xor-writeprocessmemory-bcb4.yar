rule TTP_XOR_WriteProcessMemory_bcb4 {
  strings:
    $key_bcb4 = { eb c6 [2] d9 e4 [2] df d1 [2] f1 d1 [2] ce cd }

  condition:
    any of them
}