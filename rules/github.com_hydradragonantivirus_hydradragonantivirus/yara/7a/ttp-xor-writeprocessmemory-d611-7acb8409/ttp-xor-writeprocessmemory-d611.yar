rule TTP_XOR_WriteProcessMemory_d611 {
  strings:
    $key_d611 = { 81 63 [2] b3 41 [2] b5 74 [2] 9b 74 [2] a4 68 }

  condition:
    any of them
}