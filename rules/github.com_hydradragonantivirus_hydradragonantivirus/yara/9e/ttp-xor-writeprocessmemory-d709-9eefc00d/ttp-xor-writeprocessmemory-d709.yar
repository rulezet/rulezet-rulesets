rule TTP_XOR_WriteProcessMemory_d709 {
  strings:
    $key_d709 = { 80 7b [2] b2 59 [2] b4 6c [2] 9a 6c [2] a5 70 }

  condition:
    any of them
}