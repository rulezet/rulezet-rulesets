rule TTP_XOR_WriteProcessMemory_48cb {
  strings:
    $key_48cb = { 1f b9 [2] 2d 9b [2] 2b ae [2] 05 ae [2] 3a b2 }

  condition:
    any of them
}