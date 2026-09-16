rule TTP_XOR_WriteProcessMemory_d628 {
  strings:
    $key_d628 = { 81 5a [2] b3 78 [2] b5 4d [2] 9b 4d [2] a4 51 }

  condition:
    any of them
}