rule TTP_XOR_WriteProcessMemory_7723 {
  strings:
    $key_7723 = { 20 51 [2] 12 73 [2] 14 46 [2] 3a 46 [2] 05 5a }

  condition:
    any of them
}