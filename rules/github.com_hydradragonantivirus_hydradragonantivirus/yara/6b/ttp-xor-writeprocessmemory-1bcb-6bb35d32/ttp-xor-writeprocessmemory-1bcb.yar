rule TTP_XOR_WriteProcessMemory_1bcb {
  strings:
    $key_1bcb = { 4c b9 [2] 7e 9b [2] 78 ae [2] 56 ae [2] 69 b2 }

  condition:
    any of them
}