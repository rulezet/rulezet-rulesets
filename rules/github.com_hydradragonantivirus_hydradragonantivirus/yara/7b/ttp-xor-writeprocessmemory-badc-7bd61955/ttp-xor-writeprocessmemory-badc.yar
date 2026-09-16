rule TTP_XOR_WriteProcessMemory_badc {
  strings:
    $key_badc = { ed ae [2] df 8c [2] d9 b9 [2] f7 b9 [2] c8 a5 }

  condition:
    any of them
}