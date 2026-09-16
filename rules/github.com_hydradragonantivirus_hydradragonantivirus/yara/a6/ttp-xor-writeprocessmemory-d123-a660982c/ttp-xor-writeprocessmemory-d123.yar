rule TTP_XOR_WriteProcessMemory_d123 {
  strings:
    $key_d123 = { 86 51 [2] b4 73 [2] b2 46 [2] 9c 46 [2] a3 5a }

  condition:
    any of them
}