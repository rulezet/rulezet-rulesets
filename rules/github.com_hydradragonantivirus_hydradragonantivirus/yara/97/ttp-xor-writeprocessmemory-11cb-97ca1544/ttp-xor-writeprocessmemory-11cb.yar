rule TTP_XOR_WriteProcessMemory_11cb {
  strings:
    $key_11cb = { 46 b9 [2] 74 9b [2] 72 ae [2] 5c ae [2] 63 b2 }

  condition:
    any of them
}