rule TTP_XOR_WriteProcessMemory_d174 {
  strings:
    $key_d174 = { 86 06 [2] b4 24 [2] b2 11 [2] 9c 11 [2] a3 0d }

  condition:
    any of them
}