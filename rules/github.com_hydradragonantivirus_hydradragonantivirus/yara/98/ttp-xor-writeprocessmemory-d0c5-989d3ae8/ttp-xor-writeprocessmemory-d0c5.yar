rule TTP_XOR_WriteProcessMemory_d0c5 {
  strings:
    $key_d0c5 = { 87 b7 [2] b5 95 [2] b3 a0 [2] 9d a0 [2] a2 bc }

  condition:
    any of them
}