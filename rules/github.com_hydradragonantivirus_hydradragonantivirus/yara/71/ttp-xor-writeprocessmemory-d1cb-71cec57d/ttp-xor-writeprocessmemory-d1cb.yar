rule TTP_XOR_WriteProcessMemory_d1cb {
  strings:
    $key_d1cb = { 86 b9 [2] b4 9b [2] b2 ae [2] 9c ae [2] a3 b2 }

  condition:
    any of them
}