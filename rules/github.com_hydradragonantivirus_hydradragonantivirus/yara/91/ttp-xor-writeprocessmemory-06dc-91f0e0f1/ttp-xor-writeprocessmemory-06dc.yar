rule TTP_XOR_WriteProcessMemory_06dc {
  strings:
    $key_06dc = { 51 ae [2] 63 8c [2] 65 b9 [2] 4b b9 [2] 74 a5 }

  condition:
    any of them
}