rule TTP_XOR_WriteProcessMemory_33e5 {
  strings:
    $key_33e5 = { 64 97 [2] 56 b5 [2] 50 80 [2] 7e 80 [2] 41 9c }

  condition:
    any of them
}