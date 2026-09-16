rule TTP_XOR_WriteProcessMemory_d0f6 {
  strings:
    $key_d0f6 = { 87 84 [2] b5 a6 [2] b3 93 [2] 9d 93 [2] a2 8f }

  condition:
    any of them
}