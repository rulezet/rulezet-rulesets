rule TTP_XOR_WriteProcessMemory_2215 {
  strings:
    $key_2215 = { 75 67 [2] 47 45 [2] 41 70 [2] 6f 70 [2] 50 6c }

  condition:
    any of them
}