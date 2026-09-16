rule TTP_XOR_WriteProcessMemory_77cb {
  strings:
    $key_77cb = { 20 b9 [2] 12 9b [2] 14 ae [2] 3a ae [2] 05 b2 }

  condition:
    any of them
}