rule TTP_XOR_WriteProcessMemory_6ec1 {
  strings:
    $key_6ec1 = { 39 b3 [2] 0b 91 [2] 0d a4 [2] 23 a4 [2] 1c b8 }

  condition:
    any of them
}