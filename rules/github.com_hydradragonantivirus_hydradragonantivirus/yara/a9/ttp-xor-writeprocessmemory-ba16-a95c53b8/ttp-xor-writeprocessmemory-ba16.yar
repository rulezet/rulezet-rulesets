rule TTP_XOR_WriteProcessMemory_ba16 {
  strings:
    $key_ba16 = { ed 64 [2] df 46 [2] d9 73 [2] f7 73 [2] c8 6f }

  condition:
    any of them
}