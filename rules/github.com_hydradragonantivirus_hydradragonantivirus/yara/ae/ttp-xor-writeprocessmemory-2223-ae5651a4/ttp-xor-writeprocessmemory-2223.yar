rule TTP_XOR_WriteProcessMemory_2223 {
  strings:
    $key_2223 = { 75 51 [2] 47 73 [2] 41 46 [2] 6f 46 [2] 50 5a }

  condition:
    any of them
}