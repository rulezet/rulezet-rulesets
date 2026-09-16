rule TTP_XOR_WriteProcessMemory_7ec6 {
  strings:
    $key_7ec6 = { 29 b4 [2] 1b 96 [2] 1d a3 [2] 33 a3 [2] 0c bf }

  condition:
    any of them
}