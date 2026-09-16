rule TTP_XOR_WriteProcessMemory_d110 {
  strings:
    $key_d110 = { 86 62 [2] b4 40 [2] b2 75 [2] 9c 75 [2] a3 69 }

  condition:
    any of them
}