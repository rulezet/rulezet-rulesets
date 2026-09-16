rule TTP_XOR_WriteProcessMemory_35cb {
  strings:
    $key_35cb = { 62 b9 [2] 50 9b [2] 56 ae [2] 78 ae [2] 47 b2 }

  condition:
    any of them
}