rule TTP_XOR_WriteProcessMemory_ba59 {
  strings:
    $key_ba59 = { ed 2b [2] df 09 [2] d9 3c [2] f7 3c [2] c8 20 }

  condition:
    any of them
}