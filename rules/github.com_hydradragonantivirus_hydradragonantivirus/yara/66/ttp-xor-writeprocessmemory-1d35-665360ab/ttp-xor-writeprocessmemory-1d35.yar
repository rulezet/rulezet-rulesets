rule TTP_XOR_WriteProcessMemory_1d35 {
  strings:
    $key_1d35 = { 4a 47 [2] 78 65 [2] 7e 50 [2] 50 50 [2] 6f 4c }

  condition:
    any of them
}