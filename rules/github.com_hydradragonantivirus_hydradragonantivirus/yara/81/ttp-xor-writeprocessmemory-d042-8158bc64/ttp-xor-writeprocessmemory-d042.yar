rule TTP_XOR_WriteProcessMemory_d042 {
  strings:
    $key_d042 = { 87 30 [2] b5 12 [2] b3 27 [2] 9d 27 [2] a2 3b }

  condition:
    any of them
}