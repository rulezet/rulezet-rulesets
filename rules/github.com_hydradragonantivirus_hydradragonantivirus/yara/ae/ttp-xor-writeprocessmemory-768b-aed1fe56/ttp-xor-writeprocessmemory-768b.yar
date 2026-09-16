rule TTP_XOR_WriteProcessMemory_768b {
  strings:
    $key_768b = { 21 f9 [2] 13 db [2] 15 ee [2] 3b ee [2] 04 f2 }

  condition:
    any of them
}