rule TTP_XOR_WriteProcessMemory_2ec1 {
  strings:
    $key_2ec1 = { 79 b3 [2] 4b 91 [2] 4d a4 [2] 63 a4 [2] 5c b8 }

  condition:
    any of them
}