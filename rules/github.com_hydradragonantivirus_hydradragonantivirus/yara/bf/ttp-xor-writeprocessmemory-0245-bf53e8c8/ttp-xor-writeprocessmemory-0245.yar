rule TTP_XOR_WriteProcessMemory_0245 {
  strings:
    $key_0245 = { 55 37 [2] 67 15 [2] 61 20 [2] 4f 20 [2] 70 3c }

  condition:
    any of them
}