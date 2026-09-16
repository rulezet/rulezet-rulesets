rule TTP_XOR_WriteProcessMemory_22e5 {
  strings:
    $key_22e5 = { 75 97 [2] 47 b5 [2] 41 80 [2] 6f 80 [2] 50 9c }

  condition:
    any of them
}