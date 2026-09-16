rule TTP_XOR_WriteProcessMemory_6135 {
  strings:
    $key_6135 = { 36 47 [2] 04 65 [2] 02 50 [2] 2c 50 [2] 13 4c }

  condition:
    any of them
}