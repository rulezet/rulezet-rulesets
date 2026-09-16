rule TTP_XOR_WriteProcessMemory_ba3a {
  strings:
    $key_ba3a = { ed 48 [2] df 6a [2] d9 5f [2] f7 5f [2] c8 43 }

  condition:
    any of them
}