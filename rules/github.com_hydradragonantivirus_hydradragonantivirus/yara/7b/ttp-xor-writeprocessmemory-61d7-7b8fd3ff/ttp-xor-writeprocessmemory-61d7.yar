rule TTP_XOR_WriteProcessMemory_61d7 {
  strings:
    $key_61d7 = { 36 a5 [2] 04 87 [2] 02 b2 [2] 2c b2 [2] 13 ae }

  condition:
    any of them
}