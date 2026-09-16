rule TTP_XOR_WriteProcessMemory_13cb {
  strings:
    $key_13cb = { 44 b9 [2] 76 9b [2] 70 ae [2] 5e ae [2] 61 b2 }

  condition:
    any of them
}