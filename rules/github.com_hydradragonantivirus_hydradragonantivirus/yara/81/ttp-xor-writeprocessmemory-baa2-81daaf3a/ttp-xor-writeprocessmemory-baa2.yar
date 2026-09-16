rule TTP_XOR_WriteProcessMemory_baa2 {
  strings:
    $key_baa2 = { ed d0 [2] df f2 [2] d9 c7 [2] f7 c7 [2] c8 db }

  condition:
    any of them
}