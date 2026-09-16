rule TTP_XOR_WriteProcessMemory_62f6 {
  strings:
    $key_62f6 = { 35 84 [2] 07 a6 [2] 01 93 [2] 2f 93 [2] 10 8f }

  condition:
    any of them
}