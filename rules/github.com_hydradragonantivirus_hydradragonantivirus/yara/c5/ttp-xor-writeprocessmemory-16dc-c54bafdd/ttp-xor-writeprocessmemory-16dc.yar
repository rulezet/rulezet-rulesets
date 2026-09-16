rule TTP_XOR_WriteProcessMemory_16dc {
  strings:
    $key_16dc = { 41 ae [2] 73 8c [2] 75 b9 [2] 5b b9 [2] 64 a5 }

  condition:
    any of them
}