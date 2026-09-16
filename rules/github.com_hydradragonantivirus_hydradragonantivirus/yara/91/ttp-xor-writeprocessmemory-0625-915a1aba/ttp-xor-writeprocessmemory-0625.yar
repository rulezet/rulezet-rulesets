rule TTP_XOR_WriteProcessMemory_0625 {
  strings:
    $key_0625 = { 51 57 [2] 63 75 [2] 65 40 [2] 4b 40 [2] 74 5c }

  condition:
    any of them
}