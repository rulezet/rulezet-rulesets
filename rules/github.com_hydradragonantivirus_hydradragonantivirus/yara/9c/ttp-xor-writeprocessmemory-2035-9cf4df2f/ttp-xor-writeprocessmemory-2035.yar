rule TTP_XOR_WriteProcessMemory_2035 {
  strings:
    $key_2035 = { 77 47 [2] 45 65 [2] 43 50 [2] 6d 50 [2] 52 4c }

  condition:
    any of them
}