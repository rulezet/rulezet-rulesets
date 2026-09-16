rule TTP_XOR_WriteProcessMemory_6623 {
  strings:
    $key_6623 = { 31 51 [2] 03 73 [2] 05 46 [2] 2b 46 [2] 14 5a }

  condition:
    any of them
}