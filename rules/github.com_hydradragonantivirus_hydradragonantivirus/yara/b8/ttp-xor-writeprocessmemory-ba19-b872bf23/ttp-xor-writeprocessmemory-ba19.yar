rule TTP_XOR_WriteProcessMemory_ba19 {
  strings:
    $key_ba19 = { ed 6b [2] df 49 [2] d9 7c [2] f7 7c [2] c8 60 }

  condition:
    any of them
}