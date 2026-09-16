rule TTP_XOR_WriteProcessMemory_6b9c {
  strings:
    $key_6b9c = { 3c ee [2] 0e cc [2] 08 f9 [2] 26 f9 [2] 19 e5 }

  condition:
    any of them
}