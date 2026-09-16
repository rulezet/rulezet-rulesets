rule TTP_XOR_WriteProcessMemory_baa3 {
  strings:
    $key_baa3 = { ed d1 [2] df f3 [2] d9 c6 [2] f7 c6 [2] c8 da }

  condition:
    any of them
}