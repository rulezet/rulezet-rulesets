rule TTP_XOR_WriteProcessMemory_14e5 {
  strings:
    $key_14e5 = { 43 97 [2] 71 b5 [2] 77 80 [2] 59 80 [2] 66 9c }

  condition:
    any of them
}