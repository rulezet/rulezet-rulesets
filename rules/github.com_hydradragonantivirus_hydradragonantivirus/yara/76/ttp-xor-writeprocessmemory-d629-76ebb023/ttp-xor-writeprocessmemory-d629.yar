rule TTP_XOR_WriteProcessMemory_d629 {
  strings:
    $key_d629 = { 81 5b [2] b3 79 [2] b5 4c [2] 9b 4c [2] a4 50 }

  condition:
    any of them
}