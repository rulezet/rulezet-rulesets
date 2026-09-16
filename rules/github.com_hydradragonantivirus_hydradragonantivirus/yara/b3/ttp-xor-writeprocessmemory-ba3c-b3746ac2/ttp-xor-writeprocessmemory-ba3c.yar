rule TTP_XOR_WriteProcessMemory_ba3c {
  strings:
    $key_ba3c = { ed 4e [2] df 6c [2] d9 59 [2] f7 59 [2] c8 45 }

  condition:
    any of them
}