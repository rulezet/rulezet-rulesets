rule TTP_XOR_WriteProcessMemory_bad7 {
  strings:
    $key_bad7 = { ed a5 [2] df 87 [2] d9 b2 [2] f7 b2 [2] c8 ae }

  condition:
    any of them
}