rule TTP_XOR_WriteProcessMemory_ba09 {
  strings:
    $key_ba09 = { ed 7b [2] df 59 [2] d9 6c [2] f7 6c [2] c8 70 }

  condition:
    any of them
}