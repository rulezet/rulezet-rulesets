rule TTP_XOR_WriteProcessMemory_4ecb {
  strings:
    $key_4ecb = { 19 b9 [2] 2b 9b [2] 2d ae [2] 03 ae [2] 3c b2 }

  condition:
    any of them
}