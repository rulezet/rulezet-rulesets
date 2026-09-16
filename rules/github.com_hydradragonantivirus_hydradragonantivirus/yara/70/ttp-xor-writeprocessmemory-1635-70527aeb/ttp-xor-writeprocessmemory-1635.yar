rule TTP_XOR_WriteProcessMemory_1635 {
  strings:
    $key_1635 = { 41 47 [2] 73 65 [2] 75 50 [2] 5b 50 [2] 64 4c }

  condition:
    any of them
}