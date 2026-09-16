rule TTP_XOR_WriteProcessMemory_d111 {
  strings:
    $key_d111 = { 86 63 [2] b4 41 [2] b2 74 [2] 9c 74 [2] a3 68 }

  condition:
    any of them
}