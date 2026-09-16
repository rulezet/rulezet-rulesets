rule TTP_XOR_WriteProcessMemory_03cb {
  strings:
    $key_03cb = { 54 b9 [2] 66 9b [2] 60 ae [2] 4e ae [2] 71 b2 }

  condition:
    any of them
}