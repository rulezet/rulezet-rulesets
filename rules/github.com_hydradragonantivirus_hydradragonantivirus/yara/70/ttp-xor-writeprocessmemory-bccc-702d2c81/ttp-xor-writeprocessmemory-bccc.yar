rule TTP_XOR_WriteProcessMemory_bccc {
  strings:
    $key_bccc = { eb be [2] d9 9c [2] df a9 [2] f1 a9 [2] ce b5 }

  condition:
    any of them
}