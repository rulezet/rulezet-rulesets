rule TTP_XOR_WriteProcessMemory_01dc {
  strings:
    $key_01dc = { 56 ae [2] 64 8c [2] 62 b9 [2] 4c b9 [2] 73 a5 }

  condition:
    any of them
}