rule TTP_XOR_WriteProcessMemory_d6f9 {
  strings:
    $key_d6f9 = { 81 8b [2] b3 a9 [2] b5 9c [2] 9b 9c [2] a4 80 }

  condition:
    any of them
}