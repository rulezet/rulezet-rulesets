rule TTP_XOR_WriteProcessMemory_bae5 {
  strings:
    $key_bae5 = { ed 97 [2] df b5 [2] d9 80 [2] f7 80 [2] c8 9c }

  condition:
    any of them
}