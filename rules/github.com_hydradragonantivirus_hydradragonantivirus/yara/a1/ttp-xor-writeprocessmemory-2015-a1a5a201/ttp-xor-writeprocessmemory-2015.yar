rule TTP_XOR_WriteProcessMemory_2015 {
  strings:
    $key_2015 = { 77 67 [2] 45 45 [2] 43 70 [2] 6d 70 [2] 52 6c }

  condition:
    any of them
}