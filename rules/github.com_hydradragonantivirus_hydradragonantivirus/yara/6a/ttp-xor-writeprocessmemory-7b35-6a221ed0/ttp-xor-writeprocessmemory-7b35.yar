rule TTP_XOR_WriteProcessMemory_7b35 {
  strings:
    $key_7b35 = { 2c 47 [2] 1e 65 [2] 18 50 [2] 36 50 [2] 09 4c }

  condition:
    any of them
}