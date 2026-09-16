rule TTP_XOR_WriteProcessMemory_bad8 {
  strings:
    $key_bad8 = { ed aa [2] df 88 [2] d9 bd [2] f7 bd [2] c8 a1 }

  condition:
    any of them
}