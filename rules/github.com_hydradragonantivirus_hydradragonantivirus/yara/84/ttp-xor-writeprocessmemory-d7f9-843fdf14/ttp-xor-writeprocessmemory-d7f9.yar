rule TTP_XOR_WriteProcessMemory_d7f9 {
  strings:
    $key_d7f9 = { 80 8b [2] b2 a9 [2] b4 9c [2] 9a 9c [2] a5 80 }

  condition:
    any of them
}