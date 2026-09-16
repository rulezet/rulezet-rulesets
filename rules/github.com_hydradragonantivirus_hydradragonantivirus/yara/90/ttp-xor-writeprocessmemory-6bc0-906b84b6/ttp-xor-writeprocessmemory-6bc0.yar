rule TTP_XOR_WriteProcessMemory_6bc0 {
  strings:
    $key_6bc0 = { 3c b2 [2] 0e 90 [2] 08 a5 [2] 26 a5 [2] 19 b9 }

  condition:
    any of them
}