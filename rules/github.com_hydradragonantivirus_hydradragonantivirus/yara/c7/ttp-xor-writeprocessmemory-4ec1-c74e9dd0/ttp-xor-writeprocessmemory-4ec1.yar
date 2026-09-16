rule TTP_XOR_WriteProcessMemory_4ec1 {
  strings:
    $key_4ec1 = { 19 b3 [2] 2b 91 [2] 2d a4 [2] 03 a4 [2] 3c b8 }

  condition:
    any of them
}