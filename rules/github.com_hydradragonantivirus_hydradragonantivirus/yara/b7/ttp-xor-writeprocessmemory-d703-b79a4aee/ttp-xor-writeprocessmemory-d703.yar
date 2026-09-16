rule TTP_XOR_WriteProcessMemory_d703 {
  strings:
    $key_d703 = { 80 71 [2] b2 53 [2] b4 66 [2] 9a 66 [2] a5 7a }

  condition:
    any of them
}