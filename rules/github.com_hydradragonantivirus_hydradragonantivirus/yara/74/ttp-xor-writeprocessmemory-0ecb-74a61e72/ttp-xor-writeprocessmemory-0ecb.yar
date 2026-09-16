rule TTP_XOR_WriteProcessMemory_0ecb {
  strings:
    $key_0ecb = { 59 b9 [2] 6b 9b [2] 6d ae [2] 43 ae [2] 7c b2 }

  condition:
    any of them
}