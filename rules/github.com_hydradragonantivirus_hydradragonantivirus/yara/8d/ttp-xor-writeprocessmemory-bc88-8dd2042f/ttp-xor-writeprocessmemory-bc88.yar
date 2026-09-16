rule TTP_XOR_WriteProcessMemory_bc88 {
  strings:
    $key_bc88 = { eb fa [2] d9 d8 [2] df ed [2] f1 ed [2] ce f1 }

  condition:
    any of them
}