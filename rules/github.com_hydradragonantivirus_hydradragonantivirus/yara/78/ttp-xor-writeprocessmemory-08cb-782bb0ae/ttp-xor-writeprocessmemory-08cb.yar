rule TTP_XOR_WriteProcessMemory_08cb {
  strings:
    $key_08cb = { 5f b9 [2] 6d 9b [2] 6b ae [2] 45 ae [2] 7a b2 }

  condition:
    any of them
}