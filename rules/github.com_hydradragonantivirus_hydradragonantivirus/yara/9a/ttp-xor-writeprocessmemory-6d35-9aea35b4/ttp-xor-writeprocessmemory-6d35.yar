rule TTP_XOR_WriteProcessMemory_6d35 {
  strings:
    $key_6d35 = { 3a 47 [2] 08 65 [2] 0e 50 [2] 20 50 [2] 1f 4c }

  condition:
    any of them
}