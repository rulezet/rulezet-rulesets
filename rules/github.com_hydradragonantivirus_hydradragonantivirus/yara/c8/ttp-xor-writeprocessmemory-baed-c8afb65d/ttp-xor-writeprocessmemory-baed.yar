rule TTP_XOR_WriteProcessMemory_baed {
  strings:
    $key_baed = { ed 9f [2] df bd [2] d9 88 [2] f7 88 [2] c8 94 }

  condition:
    any of them
}