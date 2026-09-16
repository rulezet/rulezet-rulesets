rule TTP_XOR_WriteProcessMemory_d1e9 {
  strings:
    $key_d1e9 = { 86 9b [2] b4 b9 [2] b2 8c [2] 9c 8c [2] a3 90 }

  condition:
    any of them
}