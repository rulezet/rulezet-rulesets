rule TTP_XOR_WriteProcessMemory_ba18 {
  strings:
    $key_ba18 = { ed 6a [2] df 48 [2] d9 7d [2] f7 7d [2] c8 61 }

  condition:
    any of them
}