rule TTP_XOR_WriteProcessMemory_1755 {
  strings:
    $key_1755 = { 40 27 [2] 72 05 [2] 74 30 [2] 5a 30 [2] 65 2c }

  condition:
    any of them
}