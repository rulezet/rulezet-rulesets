rule TTP_XOR_WriteProcessMemory_7bcb {
  strings:
    $key_7bcb = { 2c b9 [2] 1e 9b [2] 18 ae [2] 36 ae [2] 09 b2 }

  condition:
    any of them
}