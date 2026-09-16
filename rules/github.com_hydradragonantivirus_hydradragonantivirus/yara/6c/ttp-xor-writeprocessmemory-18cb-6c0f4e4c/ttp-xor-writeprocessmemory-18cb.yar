rule TTP_XOR_WriteProcessMemory_18cb {
  strings:
    $key_18cb = { 4f b9 [2] 7d 9b [2] 7b ae [2] 55 ae [2] 6a b2 }

  condition:
    any of them
}