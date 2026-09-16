rule TTP_XOR_WriteProcessMemory_bae1 {
  strings:
    $key_bae1 = { ed 93 [2] df b1 [2] d9 84 [2] f7 84 [2] c8 98 }

  condition:
    any of them
}