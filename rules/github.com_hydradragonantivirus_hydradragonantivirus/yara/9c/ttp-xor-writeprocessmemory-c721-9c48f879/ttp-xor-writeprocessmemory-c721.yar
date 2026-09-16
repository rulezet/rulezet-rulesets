rule TTP_XOR_WriteProcessMemory_c721 {
  strings:
    $key_c721 = { 90 53 [2] a2 71 [2] a4 44 [2] 8a 44 [2] b5 58 }

  condition:
    any of them
}