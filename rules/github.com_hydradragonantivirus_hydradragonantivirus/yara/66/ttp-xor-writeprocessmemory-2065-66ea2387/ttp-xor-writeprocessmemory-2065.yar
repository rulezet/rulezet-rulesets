rule TTP_XOR_WriteProcessMemory_2065 {
  strings:
    $key_2065 = { 77 17 [2] 45 35 [2] 43 00 [2] 6d 00 [2] 52 1c }

  condition:
    any of them
}