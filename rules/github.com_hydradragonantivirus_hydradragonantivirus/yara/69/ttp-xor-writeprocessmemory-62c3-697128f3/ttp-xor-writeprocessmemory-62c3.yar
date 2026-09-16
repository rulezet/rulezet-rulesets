rule TTP_XOR_WriteProcessMemory_62c3 {
  strings:
    $key_62c3 = { 35 b1 [2] 07 93 [2] 01 a6 [2] 2f a6 [2] 10 ba }

  condition:
    any of them
}