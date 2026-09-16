rule TTP_XOR_WriteProcessMemory_41cb {
  strings:
    $key_41cb = { 16 b9 [2] 24 9b [2] 22 ae [2] 0c ae [2] 33 b2 }

  condition:
    any of them
}