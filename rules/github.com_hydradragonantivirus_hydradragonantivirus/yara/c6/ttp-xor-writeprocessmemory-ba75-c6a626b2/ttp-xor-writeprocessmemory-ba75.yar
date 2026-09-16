rule TTP_XOR_WriteProcessMemory_ba75 {
  strings:
    $key_ba75 = { ed 07 [2] df 25 [2] d9 10 [2] f7 10 [2] c8 0c }

  condition:
    any of them
}