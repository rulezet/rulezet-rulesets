rule TTP_XOR_WriteProcessMemory_bcce {
  strings:
    $key_bcce = { eb bc [2] d9 9e [2] df ab [2] f1 ab [2] ce b7 }

  condition:
    any of them
}