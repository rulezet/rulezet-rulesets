rule TTP_XOR_WriteProcessMemory_20cb {
  strings:
    $key_20cb = { 77 b9 [2] 45 9b [2] 43 ae [2] 6d ae [2] 52 b2 }

  condition:
    any of them
}