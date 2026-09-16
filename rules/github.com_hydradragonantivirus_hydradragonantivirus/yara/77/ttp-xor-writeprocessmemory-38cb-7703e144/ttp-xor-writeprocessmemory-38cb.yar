rule TTP_XOR_WriteProcessMemory_38cb {
  strings:
    $key_38cb = { 6f b9 [2] 5d 9b [2] 5b ae [2] 75 ae [2] 4a b2 }

  condition:
    any of them
}