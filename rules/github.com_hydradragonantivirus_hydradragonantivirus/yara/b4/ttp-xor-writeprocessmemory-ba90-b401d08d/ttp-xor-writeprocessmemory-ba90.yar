rule TTP_XOR_WriteProcessMemory_ba90 {
  strings:
    $key_ba90 = { ed e2 [2] df c0 [2] d9 f5 [2] f7 f5 [2] c8 e9 }

  condition:
    any of them
}