rule TTP_XOR_WriteProcessMemory_ba96 {
  strings:
    $key_ba96 = { ed e4 [2] df c6 [2] d9 f3 [2] f7 f3 [2] c8 ef }

  condition:
    any of them
}