rule TTP_XOR_WriteProcessMemory_2b9c {
  strings:
    $key_2b9c = { 7c ee [2] 4e cc [2] 48 f9 [2] 66 f9 [2] 59 e5 }

  condition:
    any of them
}