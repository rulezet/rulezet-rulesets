rule TTP_XOR_WriteProcessMemory_118b {
  strings:
    $key_118b = { 46 f9 [2] 74 db [2] 72 ee [2] 5c ee [2] 63 f2 }

  condition:
    any of them
}