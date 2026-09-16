rule TTP_XOR_WriteProcessMemory_baa5 {
  strings:
    $key_baa5 = { ed d7 [2] df f5 [2] d9 c0 [2] f7 c0 [2] c8 dc }

  condition:
    any of them
}