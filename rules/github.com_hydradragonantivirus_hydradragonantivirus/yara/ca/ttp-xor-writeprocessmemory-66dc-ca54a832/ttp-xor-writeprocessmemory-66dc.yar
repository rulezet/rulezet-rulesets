rule TTP_XOR_WriteProcessMemory_66dc {
  strings:
    $key_66dc = { 31 ae [2] 03 8c [2] 05 b9 [2] 2b b9 [2] 14 a5 }

  condition:
    any of them
}