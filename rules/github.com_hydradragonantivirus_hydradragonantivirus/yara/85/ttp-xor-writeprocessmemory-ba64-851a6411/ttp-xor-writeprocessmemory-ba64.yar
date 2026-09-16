rule TTP_XOR_WriteProcessMemory_ba64 {
  strings:
    $key_ba64 = { ed 16 [2] df 34 [2] d9 01 [2] f7 01 [2] c8 1d }

  condition:
    any of them
}