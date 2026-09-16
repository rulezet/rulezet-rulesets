rule TTP_XOR_WriteProcessMemory_d176 {
  strings:
    $key_d176 = { 86 04 [2] b4 26 [2] b2 13 [2] 9c 13 [2] a3 0f }

  condition:
    any of them
}