rule TTP_XOR_WriteProcessMemory_22cb {
  strings:
    $key_22cb = { 75 b9 [2] 47 9b [2] 41 ae [2] 6f ae [2] 50 b2 }

  condition:
    any of them
}