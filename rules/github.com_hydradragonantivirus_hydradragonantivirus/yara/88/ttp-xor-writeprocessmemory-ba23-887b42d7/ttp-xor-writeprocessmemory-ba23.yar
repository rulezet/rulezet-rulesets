rule TTP_XOR_WriteProcessMemory_ba23 {
  strings:
    $key_ba23 = { ed 51 [2] df 73 [2] d9 46 [2] f7 46 [2] c8 5a }

  condition:
    any of them
}