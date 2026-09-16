rule TTP_XOR_WriteProcessMemory_7ecb {
  strings:
    $key_7ecb = { 29 b9 [2] 1b 9b [2] 1d ae [2] 33 ae [2] 0c b2 }

  condition:
    any of them
}