rule TTP_XOR_WriteProcessMemory_ba28 {
  strings:
    $key_ba28 = { ed 5a [2] df 78 [2] d9 4d [2] f7 4d [2] c8 51 }

  condition:
    any of them
}