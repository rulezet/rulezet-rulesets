rule TTP_XOR_WriteProcessMemory_ba6a {
  strings:
    $key_ba6a = { ed 18 [2] df 3a [2] d9 0f [2] f7 0f [2] c8 13 }

  condition:
    any of them
}