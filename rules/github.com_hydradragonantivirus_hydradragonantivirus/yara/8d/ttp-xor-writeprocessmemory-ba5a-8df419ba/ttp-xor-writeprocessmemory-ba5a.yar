rule TTP_XOR_WriteProcessMemory_ba5a {
  strings:
    $key_ba5a = { ed 28 [2] df 0a [2] d9 3f [2] f7 3f [2] c8 23 }

  condition:
    any of them
}