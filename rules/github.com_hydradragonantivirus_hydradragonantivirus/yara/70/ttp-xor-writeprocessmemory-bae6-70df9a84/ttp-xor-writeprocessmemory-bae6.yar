rule TTP_XOR_WriteProcessMemory_bae6 {
  strings:
    $key_bae6 = { ed 94 [2] df b6 [2] d9 83 [2] f7 83 [2] c8 9f }

  condition:
    any of them
}