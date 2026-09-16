rule TTP_XOR_WriteProcessMemory_ba36 {
  strings:
    $key_ba36 = { ed 44 [2] df 66 [2] d9 53 [2] f7 53 [2] c8 4f }

  condition:
    any of them
}