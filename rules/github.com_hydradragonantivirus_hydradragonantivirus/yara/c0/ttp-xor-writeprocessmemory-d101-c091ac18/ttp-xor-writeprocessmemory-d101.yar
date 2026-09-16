rule TTP_XOR_WriteProcessMemory_d101 {
  strings:
    $key_d101 = { 86 73 [2] b4 51 [2] b2 64 [2] 9c 64 [2] a3 78 }

  condition:
    any of them
}