rule TTP_XOR_WriteProcessMemory_61dc {
  strings:
    $key_61dc = { 36 ae [2] 04 8c [2] 02 b9 [2] 2c b9 [2] 13 a5 }

  condition:
    any of them
}