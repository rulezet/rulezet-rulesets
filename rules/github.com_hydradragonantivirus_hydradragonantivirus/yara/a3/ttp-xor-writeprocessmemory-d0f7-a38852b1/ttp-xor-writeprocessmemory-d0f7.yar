rule TTP_XOR_WriteProcessMemory_d0f7 {
  strings:
    $key_d0f7 = { 87 85 [2] b5 a7 [2] b3 92 [2] 9d 92 [2] a2 8e }

  condition:
    any of them
}