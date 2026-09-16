rule TTP_XOR_WriteProcessMemory_75e5 {
  strings:
    $key_75e5 = { 22 97 [2] 10 b5 [2] 16 80 [2] 38 80 [2] 07 9c }

  condition:
    any of them
}