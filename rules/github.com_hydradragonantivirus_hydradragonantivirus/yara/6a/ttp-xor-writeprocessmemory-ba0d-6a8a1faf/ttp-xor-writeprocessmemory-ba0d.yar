rule TTP_XOR_WriteProcessMemory_ba0d {
  strings:
    $key_ba0d = { ed 7f [2] df 5d [2] d9 68 [2] f7 68 [2] c8 74 }

  condition:
    any of them
}