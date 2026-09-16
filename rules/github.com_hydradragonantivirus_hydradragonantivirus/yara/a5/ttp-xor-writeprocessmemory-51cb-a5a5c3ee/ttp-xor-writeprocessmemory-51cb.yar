rule TTP_XOR_WriteProcessMemory_51cb {
  strings:
    $key_51cb = { 06 b9 [2] 34 9b [2] 32 ae [2] 1c ae [2] 23 b2 }

  condition:
    any of them
}