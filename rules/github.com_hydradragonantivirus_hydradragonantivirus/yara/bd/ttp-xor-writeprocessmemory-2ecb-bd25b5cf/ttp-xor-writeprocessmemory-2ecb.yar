rule TTP_XOR_WriteProcessMemory_2ecb {
  strings:
    $key_2ecb = { 79 b9 [2] 4b 9b [2] 4d ae [2] 63 ae [2] 5c b2 }

  condition:
    any of them
}