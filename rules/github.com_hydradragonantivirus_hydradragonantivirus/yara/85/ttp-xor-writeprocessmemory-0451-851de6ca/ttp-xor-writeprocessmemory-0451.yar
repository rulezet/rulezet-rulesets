rule TTP_XOR_WriteProcessMemory_0451 {
  strings:
    $key_0451 = { 53 23 [2] 61 01 [2] 67 34 [2] 49 34 [2] 76 28 }

  condition:
    any of them
}