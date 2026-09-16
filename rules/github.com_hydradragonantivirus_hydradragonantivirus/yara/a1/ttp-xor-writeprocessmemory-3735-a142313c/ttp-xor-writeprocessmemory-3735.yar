rule TTP_XOR_WriteProcessMemory_3735 {
  strings:
    $key_3735 = { 60 47 [2] 52 65 [2] 54 50 [2] 7a 50 [2] 45 4c }

  condition:
    any of them
}