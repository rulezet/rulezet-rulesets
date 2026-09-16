rule TTP_XOR_WriteProcessMemory_05dc {
  strings:
    $key_05dc = { 52 ae [2] 60 8c [2] 66 b9 [2] 48 b9 [2] 77 a5 }

  condition:
    any of them
}