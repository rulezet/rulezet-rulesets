rule TTP_XOR_WriteProcessMemory_d0f3 {
  strings:
    $key_d0f3 = { 87 81 [2] b5 a3 [2] b3 96 [2] 9d 96 [2] a2 8a }

  condition:
    any of them
}