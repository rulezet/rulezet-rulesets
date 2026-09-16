rule TTP_XOR_WriteProcessMemory_0435 {
  strings:
    $key_0435 = { 53 47 [2] 61 65 [2] 67 50 [2] 49 50 [2] 76 4c }

  condition:
    any of them
}