rule TTP_XOR_WriteProcessMemory_36cb {
  strings:
    $key_36cb = { 61 b9 [2] 53 9b [2] 55 ae [2] 7b ae [2] 44 b2 }

  condition:
    any of them
}