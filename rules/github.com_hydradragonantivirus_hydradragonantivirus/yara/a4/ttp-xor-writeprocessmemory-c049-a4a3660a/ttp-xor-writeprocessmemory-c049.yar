rule TTP_XOR_WriteProcessMemory_c049 {
  strings:
    $key_c049 = { 97 3b [2] a5 19 [2] a3 2c [2] 8d 2c [2] b2 30 }

  condition:
    any of them
}