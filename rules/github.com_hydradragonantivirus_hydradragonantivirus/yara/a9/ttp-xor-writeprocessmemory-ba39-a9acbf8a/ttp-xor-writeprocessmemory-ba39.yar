rule TTP_XOR_WriteProcessMemory_ba39 {
  strings:
    $key_ba39 = { ed 4b [2] df 69 [2] d9 5c [2] f7 5c [2] c8 40 }

  condition:
    any of them
}