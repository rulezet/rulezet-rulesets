rule TTP_XOR_WriteProcessMemory_0275 {
  strings:
    $key_0275 = { 55 07 [2] 67 25 [2] 61 10 [2] 4f 10 [2] 70 0c }

  condition:
    any of them
}