rule TTP_XOR_WriteProcessMemory_1ec6 {
  strings:
    $key_1ec6 = { 49 b4 [2] 7b 96 [2] 7d a3 [2] 53 a3 [2] 6c bf }

  condition:
    any of them
}