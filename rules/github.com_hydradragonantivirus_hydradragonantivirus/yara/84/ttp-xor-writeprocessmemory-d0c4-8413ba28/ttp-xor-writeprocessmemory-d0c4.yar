rule TTP_XOR_WriteProcessMemory_d0c4 {
  strings:
    $key_d0c4 = { 87 b6 [2] b5 94 [2] b3 a1 [2] 9d a1 [2] a2 bd }

  condition:
    any of them
}