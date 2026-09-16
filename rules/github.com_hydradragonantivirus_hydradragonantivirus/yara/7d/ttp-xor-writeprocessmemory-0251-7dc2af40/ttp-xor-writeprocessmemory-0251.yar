rule TTP_XOR_WriteProcessMemory_0251 {
  strings:
    $key_0251 = { 55 23 [2] 67 01 [2] 61 34 [2] 4f 34 [2] 70 28 }

  condition:
    any of them
}