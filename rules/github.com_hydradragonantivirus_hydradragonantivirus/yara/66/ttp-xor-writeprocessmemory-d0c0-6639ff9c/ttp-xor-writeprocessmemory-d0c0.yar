rule TTP_XOR_WriteProcessMemory_d0c0 {
  strings:
    $key_d0c0 = { 87 b2 [2] b5 90 [2] b3 a5 [2] 9d a5 [2] a2 b9 }

  condition:
    any of them
}