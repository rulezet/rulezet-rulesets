rule TTP_XOR_WriteProcessMemory_d109 {
  strings:
    $key_d109 = { 86 7b [2] b4 59 [2] b2 6c [2] 9c 6c [2] a3 70 }

  condition:
    any of them
}