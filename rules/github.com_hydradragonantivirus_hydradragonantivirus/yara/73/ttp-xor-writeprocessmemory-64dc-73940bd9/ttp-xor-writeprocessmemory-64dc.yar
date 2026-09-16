rule TTP_XOR_WriteProcessMemory_64dc {
  strings:
    $key_64dc = { 33 ae [2] 01 8c [2] 07 b9 [2] 29 b9 [2] 16 a5 }

  condition:
    any of them
}