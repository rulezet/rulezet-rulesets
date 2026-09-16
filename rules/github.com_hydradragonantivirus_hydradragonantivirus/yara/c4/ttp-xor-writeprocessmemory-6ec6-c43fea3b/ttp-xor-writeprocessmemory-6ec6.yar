rule TTP_XOR_WriteProcessMemory_6ec6 {
  strings:
    $key_6ec6 = { 39 b4 [2] 0b 96 [2] 0d a3 [2] 23 a3 [2] 1c bf }

  condition:
    any of them
}