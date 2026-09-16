rule TTP_XOR_WriteProcessMemory_ba58 {
  strings:
    $key_ba58 = { ed 2a [2] df 08 [2] d9 3d [2] f7 3d [2] c8 21 }

  condition:
    any of them
}