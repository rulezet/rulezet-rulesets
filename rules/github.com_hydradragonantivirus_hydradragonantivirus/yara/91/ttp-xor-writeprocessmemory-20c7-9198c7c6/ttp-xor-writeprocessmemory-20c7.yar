rule TTP_XOR_WriteProcessMemory_20c7 {
  strings:
    $key_20c7 = { 77 b5 [2] 45 97 [2] 43 a2 [2] 6d a2 [2] 52 be }

  condition:
    any of them
}