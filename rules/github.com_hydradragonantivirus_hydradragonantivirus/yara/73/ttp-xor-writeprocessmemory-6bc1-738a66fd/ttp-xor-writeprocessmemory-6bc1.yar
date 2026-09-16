rule TTP_XOR_WriteProcessMemory_6bc1 {
  strings:
    $key_6bc1 = { 3c b3 [2] 0e 91 [2] 08 a4 [2] 26 a4 [2] 19 b8 }

  condition:
    any of them
}