rule TTP_XOR_WriteProcessMemory_2ec6 {
  strings:
    $key_2ec6 = { 79 b4 [2] 4b 96 [2] 4d a3 [2] 63 a3 [2] 5c bf }

  condition:
    any of them
}