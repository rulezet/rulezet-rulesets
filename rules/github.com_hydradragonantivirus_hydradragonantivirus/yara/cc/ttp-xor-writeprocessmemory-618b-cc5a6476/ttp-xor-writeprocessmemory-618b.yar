rule TTP_XOR_WriteProcessMemory_618b {
  strings:
    $key_618b = { 36 f9 [2] 04 db [2] 02 ee [2] 2c ee [2] 13 f2 }

  condition:
    any of them
}