rule TTP_XOR_WriteProcessMemory_0425 {
  strings:
    $key_0425 = { 53 57 [2] 61 75 [2] 67 40 [2] 49 40 [2] 76 5c }

  condition:
    any of them
}