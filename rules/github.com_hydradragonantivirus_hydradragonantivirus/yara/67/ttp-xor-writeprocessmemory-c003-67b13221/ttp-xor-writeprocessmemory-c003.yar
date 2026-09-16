rule TTP_XOR_WriteProcessMemory_c003 {
  strings:
    $key_c003 = { 97 71 [2] a5 53 [2] a3 66 [2] 8d 66 [2] b2 7a }

  condition:
    any of them
}