rule TTP_XOR_WriteProcessMemory_d0e9 {
  strings:
    $key_d0e9 = { 87 9b [2] b5 b9 [2] b3 8c [2] 9d 8c [2] a2 90 }

  condition:
    any of them
}