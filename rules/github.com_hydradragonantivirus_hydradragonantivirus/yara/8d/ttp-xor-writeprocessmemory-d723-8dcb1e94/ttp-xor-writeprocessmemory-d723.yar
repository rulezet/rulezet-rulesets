rule TTP_XOR_WriteProcessMemory_d723 {
  strings:
    $key_d723 = { 80 51 [2] b2 73 [2] b4 46 [2] 9a 46 [2] a5 5a }

  condition:
    any of them
}