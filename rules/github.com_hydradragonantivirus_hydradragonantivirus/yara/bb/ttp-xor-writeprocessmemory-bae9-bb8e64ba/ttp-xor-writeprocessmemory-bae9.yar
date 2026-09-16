rule TTP_XOR_WriteProcessMemory_bae9 {
  strings:
    $key_bae9 = { ed 9b [2] df b9 [2] d9 8c [2] f7 8c [2] c8 90 }

  condition:
    any of them
}