rule TTP_XOR_WriteProcessMemory_2202 {
  strings:
    $key_2202 = { 75 70 [2] 47 52 [2] 41 67 [2] 6f 67 [2] 50 7b }

  condition:
    any of them
}