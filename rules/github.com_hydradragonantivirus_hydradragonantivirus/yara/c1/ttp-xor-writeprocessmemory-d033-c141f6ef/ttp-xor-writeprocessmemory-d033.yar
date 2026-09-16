rule TTP_XOR_WriteProcessMemory_d033 {
  strings:
    $key_d033 = { 87 41 [2] b5 63 [2] b3 56 [2] 9d 56 [2] a2 4a }

  condition:
    any of them
}