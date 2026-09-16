rule TTP_XOR_WriteProcessMemory_0623 {
  strings:
    $key_0623 = { 51 51 [2] 63 73 [2] 65 46 [2] 4b 46 [2] 74 5a }

  condition:
    any of them
}