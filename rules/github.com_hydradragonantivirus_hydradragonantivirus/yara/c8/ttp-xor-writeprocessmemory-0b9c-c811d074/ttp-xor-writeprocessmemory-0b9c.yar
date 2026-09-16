rule TTP_XOR_WriteProcessMemory_0b9c {
  strings:
    $key_0b9c = { 5c ee [2] 6e cc [2] 68 f9 [2] 46 f9 [2] 79 e5 }

  condition:
    any of them
}