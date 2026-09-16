rule TTP_XOR_WriteProcessMemory_12cb {
  strings:
    $key_12cb = { 45 b9 [2] 77 9b [2] 71 ae [2] 5f ae [2] 60 b2 }

  condition:
    any of them
}