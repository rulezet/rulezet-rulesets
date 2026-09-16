rule TTP_XOR_WriteProcessMemory_d036 {
  strings:
    $key_d036 = { 87 44 [2] b5 66 [2] b3 53 [2] 9d 53 [2] a2 4f }

  condition:
    any of them
}