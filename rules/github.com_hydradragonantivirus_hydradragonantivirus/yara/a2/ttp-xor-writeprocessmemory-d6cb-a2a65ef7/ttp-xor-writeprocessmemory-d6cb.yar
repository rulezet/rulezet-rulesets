rule TTP_XOR_WriteProcessMemory_d6cb {
  strings:
    $key_d6cb = { 81 b9 [2] b3 9b [2] b5 ae [2] 9b ae [2] a4 b2 }

  condition:
    any of them
}