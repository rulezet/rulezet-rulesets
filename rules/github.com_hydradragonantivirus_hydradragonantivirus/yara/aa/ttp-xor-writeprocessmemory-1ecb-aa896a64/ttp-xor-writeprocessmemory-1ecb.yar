rule TTP_XOR_WriteProcessMemory_1ecb {
  strings:
    $key_1ecb = { 49 b9 [2] 7b 9b [2] 7d ae [2] 53 ae [2] 6c b2 }

  condition:
    any of them
}