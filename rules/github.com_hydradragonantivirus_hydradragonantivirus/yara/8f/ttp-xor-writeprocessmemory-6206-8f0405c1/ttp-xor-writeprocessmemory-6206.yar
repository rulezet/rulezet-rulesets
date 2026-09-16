rule TTP_XOR_WriteProcessMemory_6206 {
  strings:
    $key_6206 = { 35 74 [2] 07 56 [2] 01 63 [2] 2f 63 [2] 10 7f }

  condition:
    any of them
}