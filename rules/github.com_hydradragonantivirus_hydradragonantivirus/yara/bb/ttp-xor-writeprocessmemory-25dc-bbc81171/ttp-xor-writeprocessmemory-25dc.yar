rule TTP_XOR_WriteProcessMemory_25dc {
  strings:
    $key_25dc = { 72 ae [2] 40 8c [2] 46 b9 [2] 68 b9 [2] 57 a5 }

  condition:
    any of them
}