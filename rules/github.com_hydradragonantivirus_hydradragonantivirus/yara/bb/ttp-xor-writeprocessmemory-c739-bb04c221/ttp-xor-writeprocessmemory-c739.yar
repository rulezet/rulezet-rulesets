rule TTP_XOR_WriteProcessMemory_c739 {
  strings:
    $key_c739 = { 90 4b [2] a2 69 [2] a4 5c [2] 8a 5c [2] b5 40 }

  condition:
    any of them
}