rule TTP_XOR_WriteProcessMemory_ba33 {
  strings:
    $key_ba33 = { ed 41 [2] df 63 [2] d9 56 [2] f7 56 [2] c8 4a }

  condition:
    any of them
}