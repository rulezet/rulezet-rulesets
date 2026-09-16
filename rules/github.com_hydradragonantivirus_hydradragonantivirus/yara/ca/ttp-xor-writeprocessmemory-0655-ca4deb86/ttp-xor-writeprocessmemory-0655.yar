rule TTP_XOR_WriteProcessMemory_0655 {
  strings:
    $key_0655 = { 51 27 [2] 63 05 [2] 65 30 [2] 4b 30 [2] 74 2c }

  condition:
    any of them
}