rule TTP_XOR_WriteProcessMemory_d076 {
  strings:
    $key_d076 = { 87 04 [2] b5 26 [2] b3 13 [2] 9d 13 [2] a2 0f }

  condition:
    any of them
}