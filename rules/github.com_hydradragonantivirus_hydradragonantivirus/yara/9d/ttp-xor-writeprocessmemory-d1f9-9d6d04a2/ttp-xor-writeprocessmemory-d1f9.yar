rule TTP_XOR_WriteProcessMemory_d1f9 {
  strings:
    $key_d1f9 = { 86 8b [2] b4 a9 [2] b2 9c [2] 9c 9c [2] a3 80 }

  condition:
    any of them
}