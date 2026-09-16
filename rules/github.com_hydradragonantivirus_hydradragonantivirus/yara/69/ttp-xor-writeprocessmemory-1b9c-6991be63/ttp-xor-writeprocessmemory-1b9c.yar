rule TTP_XOR_WriteProcessMemory_1b9c {
  strings:
    $key_1b9c = { 4c ee [2] 7e cc [2] 78 f9 [2] 56 f9 [2] 69 e5 }

  condition:
    any of them
}