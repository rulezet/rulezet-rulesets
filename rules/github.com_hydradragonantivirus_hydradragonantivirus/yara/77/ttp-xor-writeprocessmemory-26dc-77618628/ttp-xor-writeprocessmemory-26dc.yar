rule TTP_XOR_WriteProcessMemory_26dc {
  strings:
    $key_26dc = { 71 ae [2] 43 8c [2] 45 b9 [2] 6b b9 [2] 54 a5 }

  condition:
    any of them
}