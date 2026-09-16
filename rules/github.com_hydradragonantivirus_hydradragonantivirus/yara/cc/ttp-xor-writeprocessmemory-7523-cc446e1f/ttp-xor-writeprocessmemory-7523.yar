rule TTP_XOR_WriteProcessMemory_7523 {
  strings:
    $key_7523 = { 22 51 [2] 10 73 [2] 16 46 [2] 38 46 [2] 07 5a }

  condition:
    any of them
}