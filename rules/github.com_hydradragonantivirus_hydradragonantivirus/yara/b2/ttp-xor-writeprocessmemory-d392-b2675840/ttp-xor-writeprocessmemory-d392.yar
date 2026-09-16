rule TTP_XOR_WriteProcessMemory_d392 {
  strings:
    $key_d392 = { 84 e0 [2] b6 c2 [2] b0 f7 [2] 9e f7 [2] a1 eb }

  condition:
    any of them
}