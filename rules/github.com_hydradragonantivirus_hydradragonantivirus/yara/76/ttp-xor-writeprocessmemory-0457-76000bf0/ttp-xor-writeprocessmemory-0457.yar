rule TTP_XOR_WriteProcessMemory_0457 {
  strings:
    $key_0457 = { 53 25 [2] 61 07 [2] 67 32 [2] 49 32 [2] 76 2e }

  condition:
    any of them
}