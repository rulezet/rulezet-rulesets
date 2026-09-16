rule TTP_XOR_WriteProcessMemory_ba92 {
  strings:
    $key_ba92 = { ed e0 [2] df c2 [2] d9 f7 [2] f7 f7 [2] c8 eb }

  condition:
    any of them
}