rule TTP_XOR_WriteProcessMemory_d073 {
  strings:
    $key_d073 = { 87 01 [2] b5 23 [2] b3 16 [2] 9d 16 [2] a2 0a }

  condition:
    any of them
}