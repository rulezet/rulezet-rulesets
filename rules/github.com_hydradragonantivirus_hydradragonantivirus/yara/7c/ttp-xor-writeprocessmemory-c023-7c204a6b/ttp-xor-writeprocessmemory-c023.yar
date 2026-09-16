rule TTP_XOR_WriteProcessMemory_c023 {
  strings:
    $key_c023 = { 97 51 [2] a5 73 [2] a3 46 [2] 8d 46 [2] b2 5a }

  condition:
    any of them
}