rule TTP_XOR_WriteProcessMemory_c709 {
  strings:
    $key_c709 = { 90 7b [2] a2 59 [2] a4 6c [2] 8a 6c [2] b5 70 }

  condition:
    any of them
}