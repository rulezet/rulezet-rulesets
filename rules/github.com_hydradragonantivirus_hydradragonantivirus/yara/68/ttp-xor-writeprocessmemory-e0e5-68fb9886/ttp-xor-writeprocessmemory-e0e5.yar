rule TTP_XOR_WriteProcessMemory_e0e5 {
  strings:
    $key_e0e5 = { b7 97 [2] 85 b5 [2] 83 80 [2] ad 80 [2] 92 9c }

  condition:
    any of them
}