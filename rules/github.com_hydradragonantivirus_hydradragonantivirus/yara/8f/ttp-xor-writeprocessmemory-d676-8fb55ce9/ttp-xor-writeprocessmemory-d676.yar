rule TTP_XOR_WriteProcessMemory_d676 {
  strings:
    $key_d676 = { 81 04 [2] b3 26 [2] b5 13 [2] 9b 13 [2] a4 0f }

  condition:
    any of them
}