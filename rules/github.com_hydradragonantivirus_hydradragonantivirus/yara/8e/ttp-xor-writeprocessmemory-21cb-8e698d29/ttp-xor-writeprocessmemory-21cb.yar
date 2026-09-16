rule TTP_XOR_WriteProcessMemory_21cb {
  strings:
    $key_21cb = { 76 b9 [2] 44 9b [2] 42 ae [2] 6c ae [2] 53 b2 }

  condition:
    any of them
}