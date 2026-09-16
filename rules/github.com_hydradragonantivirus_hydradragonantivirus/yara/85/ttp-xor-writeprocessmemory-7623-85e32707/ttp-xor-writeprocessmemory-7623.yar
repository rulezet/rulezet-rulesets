rule TTP_XOR_WriteProcessMemory_7623 {
  strings:
    $key_7623 = { 21 51 [2] 13 73 [2] 15 46 [2] 3b 46 [2] 04 5a }

  condition:
    any of them
}