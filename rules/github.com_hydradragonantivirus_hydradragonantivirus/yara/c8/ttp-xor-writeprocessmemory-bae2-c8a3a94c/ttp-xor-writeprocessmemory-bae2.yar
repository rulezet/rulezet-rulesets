rule TTP_XOR_WriteProcessMemory_bae2 {
  strings:
    $key_bae2 = { ed 90 [2] df b2 [2] d9 87 [2] f7 87 [2] c8 9b }

  condition:
    any of them
}