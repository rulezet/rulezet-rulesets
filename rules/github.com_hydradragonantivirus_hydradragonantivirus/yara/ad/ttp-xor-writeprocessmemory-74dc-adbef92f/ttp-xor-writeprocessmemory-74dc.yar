rule TTP_XOR_WriteProcessMemory_74dc {
  strings:
    $key_74dc = { 23 ae [2] 11 8c [2] 17 b9 [2] 39 b9 [2] 06 a5 }

  condition:
    any of them
}