rule TTP_XOR_WriteProcessMemory_c7e9 {
  strings:
    $key_c7e9 = { 90 9b [2] a2 b9 [2] a4 8c [2] 8a 8c [2] b5 90 }

  condition:
    any of them
}