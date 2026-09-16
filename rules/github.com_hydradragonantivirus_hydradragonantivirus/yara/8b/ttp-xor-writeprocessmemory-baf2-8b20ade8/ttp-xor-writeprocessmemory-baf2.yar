rule TTP_XOR_WriteProcessMemory_baf2 {
  strings:
    $key_baf2 = { ed 80 [2] df a2 [2] d9 97 [2] f7 97 [2] c8 8b }

  condition:
    any of them
}