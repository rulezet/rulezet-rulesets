rule TTP_XOR_WriteProcessMemory_d623 {
  strings:
    $key_d623 = { 81 51 [2] b3 73 [2] b5 46 [2] 9b 46 [2] a4 5a }

  condition:
    any of them
}