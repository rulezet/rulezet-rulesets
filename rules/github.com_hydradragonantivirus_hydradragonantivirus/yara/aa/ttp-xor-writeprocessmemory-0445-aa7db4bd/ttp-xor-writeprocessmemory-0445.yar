rule TTP_XOR_WriteProcessMemory_0445 {
  strings:
    $key_0445 = { 53 37 [2] 61 15 [2] 67 20 [2] 49 20 [2] 76 3c }

  condition:
    any of them
}