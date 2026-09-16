rule TTP_XOR_WriteProcessMemory_1723 {
  strings:
    $key_1723 = { 40 51 [2] 72 73 [2] 74 46 [2] 5a 46 [2] 65 5a }

  condition:
    any of them
}