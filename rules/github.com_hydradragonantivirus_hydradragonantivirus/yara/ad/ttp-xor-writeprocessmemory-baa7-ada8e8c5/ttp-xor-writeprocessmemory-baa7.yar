rule TTP_XOR_WriteProcessMemory_baa7 {
  strings:
    $key_baa7 = { ed d5 [2] df f7 [2] d9 c2 [2] f7 c2 [2] c8 de }

  condition:
    any of them
}