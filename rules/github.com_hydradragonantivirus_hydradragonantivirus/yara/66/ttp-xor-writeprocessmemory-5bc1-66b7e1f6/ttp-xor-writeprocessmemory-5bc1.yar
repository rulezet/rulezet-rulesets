rule TTP_XOR_WriteProcessMemory_5bc1 {
  strings:
    $key_5bc1 = { 0c b3 [2] 3e 91 [2] 38 a4 [2] 16 a4 [2] 29 b8 }

  condition:
    any of them
}