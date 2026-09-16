rule TTP_XOR_WriteProcessMemory_1d23 {
  strings:
    $key_1d23 = { 4a 51 [2] 78 73 [2] 7e 46 [2] 50 46 [2] 6f 5a }

  condition:
    any of them
}