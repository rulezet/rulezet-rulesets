rule TTP_XOR_WriteProcessMemory_ba93 {
  strings:
    $key_ba93 = { ed e1 [2] df c3 [2] d9 f6 [2] f7 f6 [2] c8 ea }

  condition:
    any of them
}